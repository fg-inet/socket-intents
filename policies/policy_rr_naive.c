#define init policy_rr_naive_LTX_init
#define cleanup policy_rr_naive_LTX_cleanup
#define on_resolve_request policy_rr_naive_LTX_on_resolve_request
#define on_connect_request policy_rr_naive_LTX_on_connect_request

#include "policy.h"
#include "../lib/muacc_util.h"


src_prefix_list_t *spfx_cur;

int init(mam_context_t *mctx)
{
	printf("Policy module \"naive round robin\" has been loaded.\n");
	mam_print_context(mctx);
	spfx_cur = NULL;
	return 0;
}

int cleanup(mam_context_t *mctx)
{
	printf("Policy module \"naive round robin\" cleaned up.\n");
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("Resolve request - just replaing\n");
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	sa_family_t family =  rctx->ctx->remote_sa->sa_family;

	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "Connect request - dest=AF=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);
	strbuf_printf(&sb, "\n");
		
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		printf("Already bound to ");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		strbuf_printf(&sb, "\n");
		_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
		printf("%s", strbuf_export(&sb));
		strbuf_release(&sb);
		return 0;
	}

	// initalize from context if empty
	if(spfx_cur == NULL)
		spfx_cur = rctx->mctx->prefixes;
			
	// try to find matching address
	spfx_cur = lookup_source_prefix( spfx_cur, PFX_ENABLED, NULL, rctx->ctx->remote_sa->sa_family, NULL );
	
	// handle wrap around
	if(spfx_cur == NULL)
	{
		spfx_cur = rctx->mctx->prefixes;
		spfx_cur = lookup_source_prefix( spfx_cur, PFX_ENABLED, NULL, rctx->ctx->remote_sa->sa_family, NULL );
	}

	if(spfx_cur != NULL)
	{	// found matching prefix
		sockaddr_list_t *target = spfx_cur->if_addrs;
		
		strbuf_printf(&sb, "\tsuccess finding source address:\n");
		_muacc_print_sockaddr(&sb, target->addr, target->addr_len);
		
		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(target->addr, target->addr_len);
		rctx->ctx->bind_sa_suggested_len = target->addr_len;
		
		spfx_cur = spfx_cur->next;
	}
	else
	{	// failed
		strbuf_printf(&sb, "\tfailed finding source address\n");
	}	
	

	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}
