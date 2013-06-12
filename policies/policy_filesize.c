#define init policy_filesize_LTX_init
#define cleanup policy_filesize_LTX_cleanup
#define on_resolve_request policy_filesize_LTX_on_resolve_request
#define on_connect_request policy_filesize_LTX_on_connect_request

#include "policy.h"
#include "policy_util.h"
#include "../lib/muacc_util.h"
#include "../lib/intents.h"

#include <arpa/inet.h>

/* List of sockaddrs that also contains their associated filesize policies */
struct sa_fs {
	struct sa_fs			*next;
	struct sockaddr_list	*addr_list;
	socklen_t				addr_len;
	int						maxfilesize;
	int						minfilesize;
};

struct sa_fs *in4_fs_list = NULL; /* list of ipv4 addresses */
struct sa_fs *in6_fs_list = NULL; /* list of ipv6 addresses */
struct sockaddr_list *default4 = NULL;
struct sockaddr_list *default6 = NULL;

char addr_str[INET6_ADDRSTRLEN];	/** string for debug / error printing */

void setfilesize(struct src_prefix_list *spl, struct sa_fs *csa)
{
	csa->minfilesize = 0;
	csa->maxfilesize = INT_MAX;
	gpointer value = NULL;
	if ((value = g_hash_table_lookup(spl->policy_set_dict, "minfilesize")) != NULL)
	{
		csa->minfilesize = *((int *) value);
	}
	if ((value = g_hash_table_lookup(spl->policy_set_dict, "maxfilesize")) != NULL)
	{
		csa->maxfilesize = *((int *) value);
	}
	if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value)
	{
		if (csa->addr_list->addr->sa_family == AF_INET && default4 == NULL)
		{
			default4 = malloc(sizeof(struct sockaddr_list));
			memset(default4, 0, sizeof(struct sockaddr_list));
			default4->addr = _muacc_clone_sockaddr(csa->addr_list->addr, csa->addr_list->addr_len);
			default4->addr_len = csa->addr_list->addr_len;
		}
		if (csa->addr_list->addr->sa_family == AF_INET6 && default6 == NULL)
		{
			default6 = malloc(sizeof(struct sockaddr_list));
			memset(default6, 0, sizeof(struct sockaddr_list));
			default6->addr = _muacc_clone_sockaddr(csa->addr_list->addr, csa->addr_list->addr_len);
			default6->addr_len = csa->addr_list->addr_len;
		}
	}
}

void set_default_sa(sa_family_t family, strbuf_t sb, request_context_t *rctx)
{
	if (family == AF_INET && default4 != NULL)
	{
		strbuf_printf(&sb, "\n\t\tSet src=");
		_muacc_print_sockaddr(&sb, default4->addr, default4->addr_len);
		strbuf_printf(&sb, " (default)");

		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(default4->addr, default4->addr_len);
		rctx->ctx->bind_sa_suggested_len = default4->addr_len;
	}
	else if (family == AF_INET6 && default6 != NULL)
	{
		strbuf_printf(&sb, "\n\t\tSet src=");
		_muacc_print_sockaddr(&sb, default6->addr, default6->addr_len);
		strbuf_printf(&sb, " (default)");

		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(default6->addr, default6->addr_len);
		rctx->ctx->bind_sa_suggested_len = default6->addr_len;
	}
	else
	{
		strbuf_printf(&sb, "\n\t\tCannot set source address (no filesize and/or defaults given)");
	}

}

void set_sa_for_fs(struct sa_fs *list, int filesize, strbuf_t sb, request_context_t *rctx)
{
	struct sa_fs *current = list;

	while (current != NULL)
	{
		if (current->minfilesize <= filesize && current->maxfilesize >= filesize)
			break;
		current = current->next;
	}

	if (current != NULL)
	{
		strbuf_printf(&sb, "\n\t\tSet src=");
		_muacc_print_sockaddr(&sb, current->addr_list->addr, current->addr_list->addr_len);
		strbuf_printf(&sb, " for filesize %d", filesize);

		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(current->addr_list->addr, current->addr_list->addr_len);
		rctx->ctx->bind_sa_suggested_len = current->addr_list->addr_len;
	}
	else
	{
		strbuf_printf(&sb, "\n\t\tCannot find suitable address for filesize %d", filesize);
		set_default_sa(list->addr_list->addr->sa_family, sb, rctx);
	}
}


int init(mam_context_t *mctx)
{
	struct sa_fs **csa;
	struct sa_fs *prevsa = NULL;
	struct sa_fs *newsa = NULL;

	printf("Policy module \"filesize\" is loading.\n");
	printf("Building socket address lists with filesize policies: ");

	printf("\n\tAF_INET( ");
	csa = &in4_fs_list;

	for(struct src_prefix_list *spl = mctx->prefixes; spl != NULL; spl = spl->next)
	{
		spl = lookup_source_prefix( spl, PFX_ENABLED, NULL, AF_INET, NULL );
		if (spl == NULL) break;

		newsa = malloc(sizeof (struct sa_fs));
		memset(newsa, 0, sizeof(struct sa_fs));
		if (prevsa != NULL)
			prevsa->next = newsa;
		else
			(*csa) = newsa;

		newsa->addr_len = spl->if_addrs->addr_len;
		newsa->addr_list = spl->if_addrs;
		setfilesize(spl, newsa);

		inet_ntop(AF_INET, &( ((struct sockaddr_in *) (newsa->addr_list->addr))->sin_addr ), addr_str, sizeof(struct sockaddr_in));
		printf("\n\t\t%s\t(for filesize %4d =< n =< %6d)", addr_str, newsa->minfilesize, newsa->maxfilesize);
		if (default4 != NULL && (0 == memcmp(default4->addr, newsa->addr_list->addr, sizeof(struct sockaddr))))
			printf(" (default)");

		newsa->next = NULL;
		prevsa = newsa;
	}
	printf(") ");

	printf("\n\tAF_INET6 ( ");
	prevsa = NULL;
	csa = &in6_fs_list;
	for(struct src_prefix_list *spl = mctx->prefixes; spl != NULL; spl = spl->next)
	{
		spl = lookup_source_prefix( spl, PFX_ENABLED, NULL, AF_INET6, NULL );
		if (spl == NULL) break;

		newsa = malloc(sizeof (struct sockaddr_list));
		memset(newsa, 0, sizeof(struct sa_fs));
		if (prevsa != NULL)
			prevsa->next = *csa;
		else
			(*csa) = newsa;

		newsa->addr_len = spl->if_addrs->addr_len;
		newsa->addr_list = spl->if_addrs;
		setfilesize(spl, newsa);

		inet_ntop(AF_INET6, &( ((struct sockaddr_in6 *) (newsa->addr_list->addr))->sin6_addr ), addr_str, sizeof(struct sockaddr_in6));
		printf("\n\t\t%s\t(for filesize %4d =< n =< %6d)", addr_str, newsa->minfilesize, newsa->maxfilesize);
		if (default6 == newsa->addr_list)
			printf(" (default)");

		newsa->next = NULL;
		prevsa = newsa;
	}
	printf(") ");
	printf("\nPolicy module \"filesize\" has been loaded.\n");

	return 0;
}

int cleanup(mam_context_t *mctx)
{
	printf("Policy module \"filesize\" cleaned up.\n");
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("Resolve request: just replaying\n");
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

	int fs = 0;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) != 0)
	{
		// no filesize given
		set_default_sa(family, sb, rctx);
	}
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\t\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}

	else
	{
		if(family == AF_INET && in4_fs_list != NULL)
		{	// search address to bind to
			set_sa_for_fs(in4_fs_list, fs, sb, rctx);
		}
		else if(family == AF_INET6 && in6_fs_list != NULL)
		{	// search address to bind to
			set_sa_for_fs(in6_fs_list, fs, sb, rctx);
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
