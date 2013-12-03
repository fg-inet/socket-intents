
#include "policy.h"
#include "policy_util.h"

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

char addr_str[INET6_ADDRSTRLEN];	/** string for debug / error printing */

/** Setting source address: Choose the next address from the circular list */
void set_sa_rr (request_context_t *rctx, strbuf_t sb)
{
	if(rctx->ctx->domain == AF_INET && in4_enabled != NULL)
	{
		// bind to next IPv4 address, then advance in circular list
		set_bind_sa(rctx, (struct src_prefix_list *)in4_enabled->data, &sb);
		strbuf_printf(&sb, " (next in list)");
		in4_enabled = in4_enabled->next;
	}
	else if(rctx->ctx->domain == AF_INET6 && in6_enabled != NULL)
	{
		// bind to next IPv6 address, then advance in circular list
		set_bind_sa(rctx, (struct src_prefix_list *)in4_enabled->data, &sb);
		strbuf_printf(&sb, " (next in list)");
		in6_enabled = in6_enabled->next;
	}
	else
	{	// failed
		strbuf_printf(&sb, "\n\tDid not find any available address");
	}
}

int init(mam_context_t *mctx)
{
	printf("\nPolicy module \"naive round robin\" is loading.\n");

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	// Let last element point to first element again to form a circular list
	if (in4_enabled != NULL)
		g_slist_last(in4_enabled)->next = in4_enabled;
	if (in6_enabled != NULL)
		g_slist_last(in6_enabled)->next = in6_enabled;

	printf("\nPolicy module \"naive round robin\" has been loaded.\n");
	return 0;
}

int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);

	printf("Policy module \"naive round robin\" cleaned up.\n");
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("\tResolve request: Not resolving\n\n");
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		printf("\n\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}
	else
		set_sa_rr(rctx, sb);

	// send response
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}
