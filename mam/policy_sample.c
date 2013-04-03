#define init policy_sample_LTX_init
#define on_resolve_request policy_sample_LTX_on_resolve_request
#define on_connect_request policy_sample_LTX_on_connect_request

#include <stdio.h>
#include "mam.h"

int init(mam_context_t *mctx)
{
	printf("Policy sample library has been loaded.\n");
	mam_print_context(mctx);
	return 0;
}

int on_resolve_request(request_context_t *rctx)
{
	printf("Resolve request handled by policy sample library\n");
	mam_print_request_context(rctx);
	return 0;
}

int on_connect_request(request_context_t *rctx)
{
	printf("Connect request handled by policy sample library\n");
	mam_print_request_context(rctx);
	return 0;
}
