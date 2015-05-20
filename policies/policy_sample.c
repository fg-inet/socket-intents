/** \file policy_sample.c
 *  \brief Example policy to illustrate how policies work
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
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
static void set_sa_if_default(request_context_t *rctx, strbuf_t sb)
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
static void resolve_request_result(int errcode, struct evutil_addrinfo *addr, void *ptr)
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
		
		assert(addr != NULL);  
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(addr);
		evutil_freeaddrinfo(addr);
		print_addrinfo_response (rctx->ctx->remote_addrinfo_res);
	}

	// send reply
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
}

/** Resolve request function (mandatory)
 *  Is called upon each getaddrinfo request from a client
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;
	
	printf("\tResolve request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	/* Try to resolve this request using asynchronous lookup */
    req = evdns_getaddrinfo(
    		rctx->mctx->evdns_default_base, 
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result,
			rctx);
	printf(" - Sending request to default nameserver\n");
    if (req == NULL) {
		/* returned immediately  */
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
    printf("%s\n\n", strbuf_export(&sb));
    strbuf_release(&sb);

	return 0;
}

/** Asynchronous callback function for socketconnect request after resolve
 *  Invoked once a response to the resolver query has been received
 *  Sends back a reply to the client with the received answer
 */
static void resolve_request_result_connect(int errcode, struct evutil_addrinfo *addr, void *ptr)
{	
	strbuf_t sb;
	strbuf_init(&sb);

	request_context_t *rctx = ptr;
	muacc_mam_action_t action = muacc_act_socketconnect_resp;
	if (rctx->action == muacc_act_socketchoose_req)
	{
		action = muacc_act_socketchoose_resp_new;
	}

	if (errcode) {
	    printf("\n\tError resolving: %s:%s -> %s\n", rctx->ctx->remote_hostname, rctx->ctx->remote_service, evutil_gai_strerror(errcode));
		action = muacc_error_resolve;
	}
	else
	{
		printf("\n\tGot resolver response for %s: %s\n",
			rctx->ctx->remote_hostname,
			addr->ai_canonname ? addr->ai_canonname : "");
	 
		assert(addr != NULL);   
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(addr);
		print_addrinfo_response (rctx->ctx->remote_addrinfo_res);

		// Choose first result as the remote address
		rctx->ctx->domain = addr->ai_family;
		rctx->ctx->type = addr->ai_socktype;
		rctx->ctx->protocol = addr->ai_protocol;
		rctx->ctx->remote_sa_len = addr->ai_addrlen;
		rctx->ctx->remote_sa = _muacc_clone_sockaddr(addr->ai_addr, addr->ai_addrlen);

		// free libevent addrinfo
		evutil_freeaddrinfo(addr);

		// Find local address for destination
		strbuf_printf(&sb, "\tDestination address =");
		_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);
		strbuf_printf(&sb, "\n");

		if(rctx->ctx->bind_sa_req != NULL)
		{	// already bound
			strbuf_printf(&sb, "\tAlready bound to src=");
			_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
			strbuf_printf(&sb, "\n");
		}
		else
		{
			set_sa_if_default(rctx, sb);

			// search address to bind to
			if(rctx->ctx->bind_sa_suggested != NULL)
			{
				strbuf_printf(&sb, "\tSuggested address: ");
				_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_suggested, rctx->ctx->bind_sa_suggested_len);
				strbuf_printf(&sb, "\n");
			}	 
			else
				strbuf_printf(&sb, "\tNo default address available!\n");
		}
	}

	strbuf_printf(&sb, "\tSending reply\n");
	_muacc_send_ctx_event(rctx, action);

    printf("%s\n\n", strbuf_export(&sb));
    strbuf_release(&sb);
}

/** Socketconnect request function
 *  Is called upon each socketconnect request from a client
 *  Performs name resolution and then chooses a local address
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketconnect_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;
	
	printf("\tSocketconnect request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	printf(" - Sending request to default nameserver\n");

	/* Try to resolve this request using asynchronous lookup */
    req = evdns_getaddrinfo(
    		rctx->mctx->evdns_default_base, 
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result_connect,
			rctx);
    if (req == NULL) {
		/* returned immediately */
		printf("\tRequest failed.\n");
	}
	return 0;
}

/** Socketchoose request function
 *  Is called upon each socketchoose request from a client
 *  Chooses from a set of existing sockets
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;
	
	printf("\tSocketchoose request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	if (rctx->sockets != NULL)
	{
		printf("\tSuggest using socket %d\n", rctx->sockets->file);

		/* Provide the information to open a new similar socket, in case the suggested socket cannot be used */
		uuid_t context_id;
		__uuid_copy(context_id, rctx->ctx->ctxid);
		rctx->ctx = _muacc_clone_ctx(rctx->sockets->ctx);
		__uuid_copy(rctx->ctx->ctxid, context_id);

		_muacc_send_ctx_event(rctx, muacc_act_socketchoose_resp_existing);
	}
	else
	{
		printf("\tSocketchoose with empty set - trying to create new socket, resolving %s\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname));

		/* Try to resolve this request using asynchronous lookup */
		req = evdns_getaddrinfo(
    		rctx->mctx->evdns_default_base, 
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result_connect,
			rctx);
		printf(" - Sending request to default nameserver\n");
		if (req == NULL) {
			/* returned immediately  */
			printf("\tRequest failed.\n");
		}
	}

	return 0;
}
