#define init policy_intents_LTX_init
#define on_resolve_request policy_intents_LTX_on_resolve_request
#define on_connect_request policy_intents_LTX_on_connect_request

#include <stdio.h>
#include <stdlib.h>
#include <event2/event.h>

#include "policy.h"
#include "policy_util.h"

#include "../lib/intents.h"

int init(mam_context_t *mctx)
{
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
	printf("Got connect request: \n");
	mam_print_request_context(rctx);

	if (!(rctx->ctx->calls_performed & MUACC_BIND_CALLED))
	{
		/* If no bind occured yet, bind to a suitable local address */
		intent_category_t c = 0;
		socklen_t option_length = sizeof(intent_category_t);

		if (0 == mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_CATEGORY, &option_length, &c))
		{
			if (c == INTENT_QUERY)
			{
				printf("INTENT_QUERY -> use wlan0 interface if available\n");
				mampol_suggest_bind_sa(rctx, "wlan0");
			}
			else if (c == INTENT_STREAM)
			{
				printf("INTENT_STREAM -> use eth0 interface if available\n");
				mampol_suggest_bind_sa(rctx, "eth0");
			}
			else if (c == INTENT_CONTROLTRAFFIC)
			{
				printf("INTENT_CONTROLTRAFFIC -> use ppp0 interface if available\n");
				mampol_suggest_bind_sa(rctx, "ppp0");
			}
			else
			{
				printf("No policy for category %d\n", (int) c);
			}
		}
	}

	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);

	return 0;
}
