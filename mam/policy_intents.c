#define init policy_intents_LTX_init
#define on_resolve_request policy_intents_LTX_on_resolve_request
#define on_connect_request policy_intents_LTX_on_connect_request

#include <stdio.h>
#include <stdlib.h>
#include <event2/event.h>

#include "mam.h"
#include "../libintents/libintents.h"
#include "../clib/muacc.h"
#include "../clib/muacc_types.h"
#include "../clib/muacc_tlv.h"
#include "../clib/muacc_util.h"

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
		struct socketopt *current = rctx->ctx->sockopts_current;
		while (current != NULL)
		{
			if (current->level == SOL_INTENTS && current->optname == SO_CATEGORY && current->optval != NULL)
			{
				category_s *c = (category_s *) current->optval;
				if (*c == C_QUERY)
				{
					printf("C_QUERY -> use wlan0 interface if available\n");
					struct src_prefix_list *iface = rctx->mctx->prefixes;
					while (iface != NULL)
					{
						if (0 == strcmp(iface->if_name, "wlan0") && (iface->family == rctx->ctx->domain))
						{
							// use wlan0 interface if available
							rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(iface->if_addrs->addr, iface->if_addrs->addr_len);
							rctx->ctx->bind_sa_suggested_len = iface->if_addrs->addr_len;
						}
						iface = iface->next;
					}
				}
				else if (*c == C_STREAM)
				{
					printf("C_STREAM -> use eth0 interface if available\n");
					struct src_prefix_list *iface = rctx->mctx->prefixes;
					while (iface != NULL)
					{
						if (0 == strcmp(iface->if_name, "eth0") && (iface->family == rctx->ctx->domain))
						{
							// use eth0 interface if available
							rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(iface->if_addrs->addr, iface->if_addrs->addr_len);
							rctx->ctx->bind_sa_suggested_len = iface->if_addrs->addr_len;
						}
						iface = iface->next;
					}
				}
				else if (*c == C_CONTROLTRAFFIC)
				{
					printf("C_CONTROLTRAFFIC -> use ppp0 interface if available\n");
					struct src_prefix_list *iface = rctx->mctx->prefixes;
					while (iface != NULL)
					{
						if (0 == strcmp(iface->if_name, "ppp0") && (iface->family == rctx->ctx->domain))
						{
							// use ppp0 interface if available
							rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(iface->if_addrs->addr, iface->if_addrs->addr_len);
							rctx->ctx->bind_sa_suggested_len = iface->if_addrs->addr_len;
						}
						iface = iface->next;
					}
				}
			}
			current = current->next;
		}
	}

	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);

	return 0;
}
