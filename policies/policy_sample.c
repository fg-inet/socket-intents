#define init policy_sample_LTX_init
#define cleanup policy_sample_LTX_cleanup
#define on_resolve_request policy_sample_LTX_on_resolve_request
#define on_connect_request policy_sample_LTX_on_connect_request

/** Dummy to illustrate how policies work
 *  Policy_info: Whether interface has been specified as default in the config file
 *               (e.g. set default = 1 in the prefix statement)
 *  Behavior:
 *  Getaddrinfo - Resolve names using the default dns_base from the MAM context
 *  Connect     - Choose the default interface if available
 */

#include "policy.h"
#include "policy_util.h"

/** Policy-specific per-prefix data structure that contains additional information */
struct sample_info {
	int is_default;
};

/** List of enabled addresses for each address family */
GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

/** Helper to set the policy information for each prefix
 *  Here, check if this prefix has been configured as default
 */
void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct sample_info *new = malloc(sizeof(struct sample_info));
	new->is_default = 0;

	if (spl->policy_set_dict != NULL)
	{
		gpointer value = NULL;
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value )
			new->is_default = 1;
	}
	spl->policy_info = new;
}

/** Helper to print additional information given to the policy
 */
void print_policy_info(void *policy_info)
{
	struct sample_info *info = policy_info;
	if (info->is_default)
		printf(" (default)");
}

void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if (spl->policy_info != NULL)
		free(spl->policy_info);

	spl->policy_info = NULL;
}

/** Helper to set the source address to the default interface,
 *  if any exists for the requested address family
 */
void set_sa_if_default(request_context_t *rctx, strbuf_t sb)
{
	GSList *spl = NULL;
	struct src_prefix_list *cur = NULL;
	struct sample_info *info = NULL;

	if (rctx->ctx->domain == AF_INET)
		spl = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		spl = in6_enabled;

	while (spl != NULL)
	{
		cur = spl->data;
		info = (struct sample_info *)cur->policy_info;
		if (info != NULL && info->is_default)
		{
			/* This prefix is configured as default. Set source address */
			set_bind_sa(rctx, cur, &sb);
			strbuf_printf(&sb, " (default)");
			break;
		}
		spl = spl->next;
	}
}

/** Initializer function (mandatory)
 *  Is called once the policy is loaded and every time it is reloaded
 *  Typically sets the policy_info and initializes the lists of candidate addresses
 */
int init(mam_context_t *mctx)
{
	printf("Policy module \"sample\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	printf("\nPolicy module \"sample\" has been loaded.\n");
	return 0;
}

/** Cleanup function (mandatory)
 *  Is called once the policy is torn down, e.g. if MAM is terminates
 *  Tear down lists of candidate addresses (no deep free) and policy infos
 */
int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);

	printf("Policy sample library cleaned up.\n");
	return 0;
}

/** Asynchronous callback function for resolve request
 *  Invoked once a response to the resolver query has been received
 *  Sends back a reply to the client with the received answer
 */
void resolve_request_result(int errcode, struct evutil_addrinfo *addr, void *ptr) 
{
	
	request_context_t *rctx = ptr;

	if (errcode) {
	    printf("\n\tError resolving: %s -> %s\n", rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
	}
	else
	{
		printf("\n\tGot resolver response for %s: %s\n",
			rctx->ctx->remote_hostname,
			addr->ai_canonname ? addr->ai_canonname : "");
	    
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = addr;
		print_addrinfo_response (rctx->ctx->remote_addrinfo_res);
	}

	// send reply
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	
	// hack - free addr first the evutil way
   	if(addr != NULL) evutil_freeaddrinfo(addr);
	rctx->ctx->remote_addrinfo_res = NULL;
	// then let mam clean up the remainings
   	mam_release_request_context(rctx);
	
}

/** Resolve request function (mandatory)
 *  Is called upon each getaddrinfo request from a client
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;
	
	printf("\tResolve request: %s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname));

	/* Try to resolve this request using asynchronous lookup */
    req = evdns_getaddrinfo(
    		rctx->mctx->evdns_default_base, 
			rctx->ctx->remote_hostname,
			NULL /* no service name given */,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result,
			rctx);
	printf(" - Sending request to default nameserver\n");
    if (req == NULL) {
		/* returned immediately - Send reply to the client */
		_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
		mam_release_request_context(rctx);
		printf("\tRequest failed.\n");
	}
	return 0;
}

/** Connect request function (mandatory)
 *  Is called upon each connect request from a client
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}
	else
	{
		// search address to bind to
		set_sa_if_default(rctx, sb);
	}

	// send response back
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	mam_release_request_context(rctx);
    printf("%s\n\n", strbuf_export(&sb));
    strbuf_release(&sb);

	return 0;
}
