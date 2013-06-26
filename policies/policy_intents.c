#define init policy_intents_LTX_init
#define cleanup policy_intents_LTX_cleanup
#define on_resolve_request policy_intents_LTX_on_resolve_request
#define on_connect_request policy_intents_LTX_on_connect_request

#include <stdio.h>
#include <stdlib.h>

#include "policy.h"
#include "policy_util.h"
#include "../lib/muacc_util.h"

#include "../lib/intents.h"

/* policy-specific data structure */
struct intents_info {
	enum intent_category	category;
	char					*category_string;
	int						is_default;
};

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

char addr_str[INET6_ADDRSTRLEN]; /** String for debug / error printing */

void print_policy_info(void *policy_info)
{
	struct intents_info *info = policy_info;
	if (info->category_string != NULL)
		printf("\t for category %s (%d)", info->category_string, (int) info->category);
	if (info->is_default)
		printf(" (default)");
}

/* Parse category information from config file and place it into policy_info of prefix */
void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct intents_info *new = malloc(sizeof(struct intents_info));
	memset(new, 0, sizeof(struct intents_info));
	new->category = -1;

	if (spl->policy_set_dict != NULL)
	{
		/* Set category */
		gpointer value = NULL;
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "category")) != NULL)
		{
			enum intent_category cat = -1;
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
			{
				/* found valid category in config file */
				new->category = cat;
				asprintf(&(new->category_string), "%s", (char *) value);
			}
		}

		/* Set default interface */
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value)
			new->is_default = 1;
	}

	spl->policy_info = (void *) new;
}

/** Free the policy data structures */
void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if(spl->policy_info != NULL)
	{
		if(((struct intents_info *)spl->policy_info)->category_string != NULL)
			free(((struct intents_info *)spl->policy_info)->category_string);
		free(spl->policy_info);
	}
}


/* Set the matching source address for a given category */
void set_sa_for_category(GSList *spl, enum intent_category given, request_context_t *rctx, strbuf_t sb)
{
	struct src_prefix_list *cur = NULL;

	while (spl != NULL)
	{
		cur = spl->data;
		enum intent_category cat = ((struct intents_info *)cur->policy_info)->category;

		if (cat == given)
		{
			/* Category matches. Set source address */
			strbuf_printf(&sb, "\n\tSet src=");
			_muacc_print_sockaddr(&sb, cur->if_addrs->addr, cur->if_addrs->addr_len);
			strbuf_printf(&sb, " for category %s (%d)", ((struct intents_info *)cur->policy_info)->category_string, given);

			rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(cur->if_addrs->addr, cur->if_addrs->addr_len);
			rctx->ctx->bind_sa_suggested_len = cur->if_addrs->addr_len;
			break;
		}
		else
			spl = spl->next;
	}

	if (spl == NULL)
		strbuf_printf(&sb, "\n\tDid not find a suitable src address for category %d", given);
}

int init(mam_context_t *mctx)
{
	printf("Policy module \"intents\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	printf("Configured addresses:");
	printf("\n\tAF_INET: ");
	filter_prefix_list (mctx->prefixes, &in4_enabled, PFX_ENABLED, NULL, AF_INET, NULL);
	if (in4_enabled != NULL)
		g_slist_foreach(in4_enabled, &print_pfx_addr, NULL);
	else
		printf("\n\t\t(none)");

	printf("\n\tAF_INET6: ");
	filter_prefix_list (mctx->prefixes, &in6_enabled, PFX_ENABLED, NULL, AF_INET6, NULL);
	if (in6_enabled != NULL)
		g_slist_foreach(in6_enabled, &print_pfx_addr, NULL);
	else
		printf("\n\t\t(none)");

	printf("\nPolicy module \"intents\" has been loaded.\n");

	return 0;
}

int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);
	printf("Policy module \"intents\" cleaned up.\n");
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("\tResolve request: \n\n");
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	sa_family_t family =  rctx->ctx->remote_sa->sa_family;

	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	intent_category_t c = 0;
	socklen_t option_length = sizeof(intent_category_t);

	if (0 != mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_CATEGORY, &option_length, &c))
	{
		// no category given
		strbuf_printf(&sb, "\n\tNo category intent given - Policy does not apply.");
	}
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}

	else
	{
		// search address to bind to
		if (family == AF_INET && in4_enabled != NULL)
			set_sa_for_category(in4_enabled, c, rctx, sb);
		else if (family == AF_INET6 && in6_enabled != NULL)
			set_sa_for_category(in6_enabled, c, rctx, sb);
	}

	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}
