#define init policy_rr_naive_LTX_init
#define cleanup policy_rr_naive_LTX_cleanup
#define on_resolve_request policy_rr_naive_LTX_on_resolve_request
#define on_connect_request policy_rr_naive_LTX_on_connect_request

#include "policy.h"
#include "../lib/muacc_util.h"

#include <arpa/inet.h>

struct sockaddr_list *in4_rr_list = NULL; /* circular list of ipv4 addresses */ 
struct sockaddr_list *in6_rr_list = NULL; /* circular list of ipv6 addresses */ 

char addr_str[INET6_ADDRSTRLEN];	/** string for debug / error printing */

int init(mam_context_t *mctx)
{
	
	struct sockaddr_list **csa;
		
	printf("Policy module \"naive round robin\" is loading.\n");
		
	printf("Building socket address lists: ");
	
	printf("\n\tAF_INET  ( ");
	csa = &in4_rr_list;
	for(struct src_prefix_list *spl = mctx->prefixes; spl != NULL; spl = spl->next)
	{
		spl = lookup_source_prefix( spl, PFX_ENABLED, NULL, AF_INET, NULL );
		if (spl == NULL) break;
		
		 *csa = malloc(sizeof (struct sockaddr_list));
		(*csa)->addr_len = spl->if_addrs->addr_len;
		(*csa)->addr     = spl->if_addrs->addr;

		inet_ntop(AF_INET, &( ((struct sockaddr_in *) ((*csa)->addr))->sin_addr ), addr_str, sizeof(struct sockaddr_in));
		printf("%s ", addr_str);

		csa = &((*csa)->next);
	}
	if (in4_rr_list != NULL) *csa = in4_rr_list;
	printf(") ");
	
	printf("\n\tAF_INET6 ( ");
	csa = &in6_rr_list;
	for(struct src_prefix_list *spl = mctx->prefixes; spl != NULL; spl = spl->next)
	{
		spl = lookup_source_prefix( spl, PFX_ENABLED, NULL, AF_INET6, NULL );
		if (spl == NULL) break;
		
		 *csa = malloc(sizeof (struct sockaddr_list));
		(*csa)->addr_len = spl->if_addrs->addr_len;
		(*csa)->addr     = spl->if_addrs->addr;

		inet_ntop(AF_INET6, &( ((struct sockaddr_in6 *) ((*csa)->addr))->sin6_addr ), addr_str, sizeof(struct sockaddr_in6));
		printf("%s ", addr_str);

		csa = &((*csa)->next);
	}
	if (in6_rr_list != NULL) *csa = in4_rr_list;
	printf(") ");
		
	printf("\nPolicy module \"naive round robin\" has been loaded.\n");

	return 0;
}

int cleanup(mam_context_t *mctx)
{
	printf("Policy module \"naive round robin\" cleaned up.\n");
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("Resolve request: just replaing\n");
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	sa_family_t family =  rctx->ctx->remote_sa->sa_family;

	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "Connect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);
		
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		printf("\n                 already bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}
	else if(family == AF_INET && in4_rr_list != NULL)
	{	// something to bind to
		strbuf_printf(&sb, "\n                 set src=");
		_muacc_print_sockaddr(&sb, in4_rr_list->addr, in4_rr_list->addr_len);
		
		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(in4_rr_list->addr, in4_rr_list->addr_len);
		rctx->ctx->bind_sa_suggested_len = in4_rr_list->addr_len;
		
		in4_rr_list = in4_rr_list->next;
	}
	else if(family == AF_INET6 && in6_rr_list != NULL)
	{	// something to bind to
		strbuf_printf(&sb, "\n                 set src=");
		_muacc_print_sockaddr(&sb, in6_rr_list->addr, in6_rr_list->addr_len);
		
		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(in6_rr_list->addr, in6_rr_list->addr_len);
		rctx->ctx->bind_sa_suggested_len = in6_rr_list->addr_len;
		
		in4_rr_list = in6_rr_list->next;
	}
	else
	{	// failed
		strbuf_printf(&sb, "\n                 cannot provide src");
	}	
	
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}
