#define init policy_sample_LTX_init
#define on_resolve_request policy_sample_LTX_on_resolve_request
#define on_connect_request policy_sample_LTX_on_connect_request

#include <stdio.h>
#include "mam.h"
#include <event2/event.h>

#include "../clib/muacc.h"
#include "../clib/muacc_types.h"
#include "../clib/muacc_tlv.h"

int init(mam_context_t *mctx)
{
	printf("Policy sample library has been loaded.\n");
	mam_print_context(mctx);
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("Resolve request handled by policy sample library\n");
	mam_print_request_context(rctx);
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	printf("Connect request handled by policy sample library\n");
	mam_print_request_context(rctx);
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	return 0;
}
