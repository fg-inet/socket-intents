#define init policy_sample_LTX_init
#define cleanup policy_sample_LTX_cleanup
#define on_resolve_request policy_sample_LTX_on_resolve_request
#define on_connect_request policy_sample_LTX_on_connect_request

#include "policy.h"

int init(mam_context_t *mctx)
{
	printf("Policy sample library has been loaded.\n");
	mam_print_context(mctx);
	return 0;
}

int cleanup(mam_context_t *mctx)
{
	printf("Policy sample library cleaned up.\n");
	return 0;
}

void resolve_request_result(int errcode, struct evutil_addrinfo *addr, void *ptr) 
{
	
	request_context_t *rctx = ptr;

	if (errcode) {
	    printf("Error resolving: %s -> %s\n", rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
	} else {
		
		printf("Resolver library returned for %s: %s\n",
			rctx->ctx->remote_hostname,
			addr->ai_canonname ? addr->ai_canonname : "");
	    
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = addr;
		
		mam_print_request_context(rctx);		
	}

	// send reply
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	
	// hack - free addr first the evutil way
   	if(addr != NULL) evutil_freeaddrinfo(addr);
	rctx->ctx->remote_addrinfo_res = NULL;
	// then let mam clean up the remainings
   	mam_release_request_context(rctx);
	
	printf("/**************************************/\n");
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;
	
	printf("Resolve request handled by policy sample library\n");
	mam_print_request_context(rctx);
	
    req = evdns_getaddrinfo(
    		rctx->mctx->evdns_default_base, 
			rctx->ctx->remote_hostname,
			NULL /* no service name given */,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result,
			rctx);
    if (req == NULL) {
		/* returned immidiatly */
		_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
		mam_release_request_context(rctx);
	}
	printf("/**************************************/\n");
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	printf("Connect request handled by policy sample library\n");
	mam_print_request_context(rctx);
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	mam_release_request_context(rctx);
	printf("/**************************************/\n");
	return 0;
}
