#define init policy_intents_LTX_init
#define cleanup policy_intents_LTX_cleanup
#define on_resolve_request policy_intents_LTX_on_resolve_request
#define on_connect_request policy_intents_LTX_on_connect_request

#include <stdio.h>
#include <stdlib.h>
#include <event2/event.h>
#include <arpa/inet.h>

#include "policy.h"
#include "policy_util.h"
#include "../lib/muacc_util.h"

#include "../lib/intents.h"

struct sa_cat {
	struct sa_cat 			*next;
	struct sockaddr_list 	*addr_list;
	socklen_t				addr_len;
	enum intent_category	category;
	char 					*category_string;
};

struct sa_cat *in4_list = NULL;
struct sa_cat *in6_list = NULL;

char addr_str[INET6_ADDRSTRLEN]; /** String for debug / error printing */

void setcategory(struct src_prefix_list *spl, struct sa_cat *csa)
{
	csa->category = -1;
	gpointer value = NULL;
	if ((value = g_hash_table_lookup(spl->policy_set_dict, "category")) != NULL)
	{
		enum intent_category cat = -1;
		asprintf(&(csa->category_string), "%s", (char *) value);

		if (strcmp(value, "bulktransfer") == 0)
			cat = INTENT_BULKTRANSFER;
		else if (strcmp(value, "query") == 0)
			cat = INTENT_QUERY;
		else if (strcmp(value, "controltraffic") == 0)
			cat = INTENT_CONTROLTRAFFIC;
		else if (strcmp(value, "keepalives") == 0)
			cat = INTENT_KEEPALIVES;
		else if (strcmp(value, "stream") == 0)
			cat = INTENT_STREAM;
		else
			printf("WARNING: Cannot set invalid category %s\n", (char *)value);

		if (cat >= 0 && cat <= INTENT_STREAM)
			csa->category = cat;
	}
}

void set_sa_for_category(struct sa_cat *list, enum intent_category cat, strbuf_t sb, request_context_t *rctx)
{
	struct sa_cat *current = list;

	while (current != NULL)
	{
		if (current->category == cat)
			break;
		current = current->next;
	}

	if (current != NULL)
	{
		strbuf_printf(&sb, "\n\t\tSet src=");
		_muacc_print_sockaddr(&sb, current->addr_list->addr, current->addr_list->addr_len);
		strbuf_printf(&sb, " for category %s (%d)", current->category_string, cat);

		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(current->addr_list->addr, current->addr_list->addr_len);
		rctx->ctx->bind_sa_suggested_len = current->addr_list->addr_len;
	}
	else
		strbuf_printf(&sb, "\n\t\tDid not find a suitable src address for category %d", cat);
}


int init(mam_context_t *mctx)
{
	struct sa_cat **csa;
	struct sa_cat *prevsa = NULL;
	struct sa_cat *newsa = NULL;

	printf("Policy module \"intents\" is loading.\n");
	printf("Building socket address lists with intent policies: ");

	printf("\n\tAF_INET( ");
	csa = &in4_list;

	for(struct src_prefix_list *spl = mctx->prefixes; spl != NULL; spl = spl->next)
	{
		spl = lookup_source_prefix( spl, PFX_ENABLED, NULL, AF_INET, NULL );
		if (spl == NULL) break;

		newsa = malloc(sizeof (struct sa_cat));
		memset(newsa, 0, sizeof(struct sa_cat));
		if (prevsa != NULL)
			prevsa->next = newsa;
		else
			(*csa) = newsa;

		newsa->addr_len = spl->if_addrs->addr_len;
		newsa->addr_list = spl->if_addrs;
		setcategory(spl, newsa);

		inet_ntop(AF_INET, &( ((struct sockaddr_in *) (newsa->addr_list->addr))->sin_addr ), addr_str, sizeof(struct sockaddr_in));
		printf("\n\t\t%s\t(for category %s (%d))", addr_str, newsa->category_string, (int) newsa->category);

		newsa->next = NULL;
		prevsa = newsa;
	}
	printf(") ");

	printf("\n\tAF_INET6 ( ");
	prevsa = NULL;
	csa = &in6_list;
	for(struct src_prefix_list *spl = mctx->prefixes; spl != NULL; spl = spl->next)
	{
		spl = lookup_source_prefix( spl, PFX_ENABLED, NULL, AF_INET6, NULL );
		if (spl == NULL) break;

		newsa = malloc(sizeof (struct sa_cat));
		memset(newsa, 0, sizeof(struct sa_cat));
		if (prevsa != NULL)
			prevsa->next = newsa;
		else
			(*csa) = newsa;

		newsa->addr_len = spl->if_addrs->addr_len;
		newsa->addr_list = spl->if_addrs;
		setcategory(spl, newsa);

		inet_ntop(AF_INET6, &( ((struct sockaddr_in6 *) (newsa->addr_list->addr))->sin6_addr ), addr_str, sizeof(struct sockaddr_in6));
		printf("\n\t\t%s\t(for category %s (%d))", addr_str, newsa->category_string, (int) newsa->category);

		newsa->next = NULL;
		prevsa = newsa;
	}
	printf(") ");
	printf("\nPolicy module \"intents\" has been loaded.\n");

	return 0;
}

int cleanup(mam_context_t *mctx)
{
	printf("Policy module \"intents\" cleaned up.\n");
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("Got resolve request: \n");
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	sa_family_t family =  rctx->ctx->remote_sa->sa_family;

	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\t\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	intent_category_t c = 0;
	socklen_t option_length = sizeof(intent_category_t);

	if (0 != mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_CATEGORY, &option_length, &c))
	{
		// no category given
		strbuf_printf(&sb, "\n\t\tNo category intent given - Policy does not apply.");
	}
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\t\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}

	else
	{
		if(family == AF_INET && in4_list != NULL)
		{	// search address to bind to
			set_sa_for_category(in4_list, c, sb, rctx);
		}
		else if(family == AF_INET6 && in6_list != NULL)
		{	// search address to bind to
			set_sa_for_category(in6_list, c, sb, rctx);
		}
		else
		{	// failed
			strbuf_printf(&sb, "\n\t\tCannot provide src address");
		}
	}

	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}
