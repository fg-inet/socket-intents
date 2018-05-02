/** \file policy_sample.c
 *  \brief Example policy to illustrate how policies work
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Policy_info: Data structure for each prefix
 *               In this policy: Has this prefix been specified as default in the config file?
 *               (e.g. set default = 1 in the prefix statement)
 *  Behavior:
 *  Resolve Request - Resolve names using the default dns_base from the MAM context
 *  Connect         - Choose the default prefix if available
 *  Socketconnect   - Choose the default prefix if available, resolve name on its dns_base if available
 *  Socketchoose    - From list of available sockets, choose first one, else do same as socketconnect
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

static const char *logfile = NULL;

struct src_prefix_list *get_default_prefix(request_context_t *rctx, strbuf_t *sb);
int resolve_name(request_context_t *rctx);

/** Helper to set the policy information for each prefix
 *  Here, set is_default if prefix has been set as default in the config file
 */
void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct sample_info *new = malloc(sizeof(struct sample_info));
	new->is_default = 0;

	// Query the config dictionary for this prefix
	if (spl->policy_set_dict != NULL)
	{
		gpointer value = NULL;
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value )
			new->is_default = 1;
	}
	spl->policy_info = new;
}

/** Helper to print policy info
 */
void print_policy_info(void *policy_info)
{
	struct sample_info *info = policy_info;
	if (info->is_default)
		printf(" (default)");
}

/** Helper to free policy info at cleanup time */
void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if (spl->policy_info != NULL)
		free(spl->policy_info);

	spl->policy_info = NULL;
}

/** Helper function
 *  Returns the default prefix, if any exists, otherwise NULL
 */
struct src_prefix_list *get_default_prefix(request_context_t *rctx, strbuf_t *sb)
{
	GSList *spl = NULL;
	struct src_prefix_list *cur = NULL;
	struct sample_info *info = NULL;

	// If address family is specified, only look in its list, else look in both (v4 first)
	if (rctx->ctx->domain == AF_INET)
		spl = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		spl = in6_enabled;
	else
		spl = g_slist_concat(in4_enabled, in6_enabled);

	// Go through list of src prefixes
	while (spl != NULL)
	{
		// Look at per-prefix policy information
		cur = spl->data;
		info = (struct sample_info *)cur->policy_info;
		if (info != NULL && info->is_default)
		{
			/* This prefix is configured as default. Return it */
			strbuf_printf(sb, "\tFound default prefix ");
	        _muacc_print_sockaddr(sb, cur->if_addrs->addr, cur->if_addrs->addr_len);
			strbuf_printf(sb, "\n");
			return cur;
		}
		spl = spl->next;
	}
	strbuf_printf(sb, "\tDid not find a default prefix %s%s\n", (rctx->ctx->domain == AF_INET) ? "for IPv4" : "", (rctx->ctx->domain == AF_INET6) ? "for IPv6" : "");

	return NULL;
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

	logfile = g_hash_table_lookup(mctx->policy_set_dict, "logfile");
	if (logfile != NULL)
	{
		printf("\nLogging to %s\n", logfile);
	}

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

	in4_enabled = NULL;
	in6_enabled = NULL;

	printf("Policy sample library cleaned up.\n");
	return 0;
}

/** Asynchronous callback function for resolve_name
 *  Invoked once a response to the resolver query has been received
 *  Sends back a reply to the client with the received answer
 */
static void resolve_request_result(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	request_context_t *rctx = ptr;

	strbuf_t sb;
	strbuf_init(&sb);

	if (errcode) {
	    strbuf_printf(&sb, "\t[%.6f] Error resolving: %s -> %s\n", gettimestamp(), rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
		rctx->action = muacc_error_resolve;
	}
	else
	{
		// Successfully resolved name
		strbuf_printf(&sb, "\t[%.6f] Got resolver response for %s %s\n",
			gettimestamp(),
			rctx->ctx->remote_hostname,
			addr->ai_canonname ? addr->ai_canonname : "");
		
		strbuf_printf(&sb, "\t");
		_muacc_print_addrinfo(&sb, addr);
		strbuf_printf(&sb, "\n");

		// Clone result into the request context
		assert(addr != NULL);  
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(addr);

		// Choose first result as the remote address
		rctx->ctx->domain = addr->ai_family;
		rctx->ctx->type = addr->ai_socktype;
		rctx->ctx->protocol = addr->ai_protocol;
		rctx->ctx->remote_sa_len = addr->ai_addrlen;
		rctx->ctx->remote_sa = _muacc_clone_sockaddr(addr->ai_addr, addr->ai_addrlen);

		// Print remote address
		strbuf_printf(&sb, "\n\tSet remote address =");
		_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);
		strbuf_printf(&sb, "\n");

        //strbuf_release(&sb);
		evutil_freeaddrinfo(addr);
	}

	// send reply to client
	strbuf_printf(&sb, "\n\t[%.6f] Sending reply\n", gettimestamp());
	_muacc_send_ctx_event(rctx, rctx->action);

    printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);
    printf("\n\t[%.6f] Returning resolve result callback\n\n", gettimestamp());
}

/* Helper function that issues a DNS request
   and registers the callback resolve_request_result */
int resolve_name(request_context_t *rctx)
{
	strbuf_t sb;
	strbuf_init(&sb);

	struct evdns_base *evdns_base = rctx->evdns_base;

	// If no dns base is given for the chosen source prefix, use default dns base
	if (evdns_base == NULL) {
		strbuf_printf(&sb, "\tNo prefix-specific DNS base found - using default DNS base\n");
		evdns_base = rctx->mctx->evdns_default_base;
	}

	// Set hints to resolve name for our chosen address family
	if (rctx->ctx->remote_addrinfo_hint != NULL) {
		rctx->ctx->remote_addrinfo_hint->ai_family = rctx->ctx->domain;
	}
	else
	{
		// Initialize hints for address resolution
		rctx->ctx->remote_addrinfo_hint = malloc(sizeof(struct addrinfo));
		memset(rctx->ctx->remote_addrinfo_hint, 0, sizeof(struct addrinfo));
		rctx->ctx->remote_addrinfo_hint->ai_family = rctx->ctx->domain;
		rctx->ctx->remote_addrinfo_hint->ai_socktype = rctx->ctx->type;
		rctx->ctx->remote_addrinfo_hint->ai_protocol = rctx->ctx->protocol;
	}

	if (evdns_base_set_option(evdns_base, "timeout", "1") < 0)
	{
		strbuf_printf(&sb, "Setting DNS timeout failed\n");
	}

	strbuf_printf(&sb, "\t[%.6f] Resolving: %s:%s with hint: ", gettimestamp(), (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	_muacc_print_addrinfo(&sb, rctx->ctx->remote_addrinfo_hint);
	strbuf_printf(&sb, "\n");

	/* Try to resolve this request using asynchronous lookup */
	assert(evdns_base != NULL);
    evdns_getaddrinfo(
    		evdns_base,
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result,
			rctx);

    printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);

	printf("\t[%.6f] Returning resolve_name.\n\n", gettimestamp());
	return 0;
}

/** Resolve request function (mandatory)
 *  Is called upon each getaddrinfo request from a client
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("\n\t[%.6f] Resolve request: %s:%s\n\n", gettimestamp(), (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		printf("\tBind interface already specified\n");
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;

		struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
		if (bind_pfx != NULL) {
			// Set DNS base to this prefix's
			rctx->evdns_base = bind_pfx->evdns_base;
			printf("\tSet DNS base\n");
		}
	}

	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		printf("Bind interface already specified\n");
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;

		struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
		if (bind_pfx != NULL) {
			// Set DNS base to this prefix's
			rctx->evdns_base = bind_pfx->evdns_base;
			printf("Set DNS base\n");
		}
	}

	rctx->action = muacc_act_getaddrinfo_resolve_resp;

	printf("\n\t[%.6f] Calling resolve_name\n", gettimestamp());
	return resolve_name(rctx);
}

/** Connect request function (mandatory)
 *  Is called upon each connect request from a client
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\t[%.6f] Connect request: dest=", gettimestamp());
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	// Check if client has already chosen a source address to bind to
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;
	}
	else
	{
		// search default address, and set it as bind_sa in the request context if found
		struct src_prefix_list *bind_pfx = get_default_prefix(rctx, &sb);
		if (bind_pfx != NULL) {
			_muacc_logtofile(logfile, "%s_default\n", bind_pfx->if_name);
			set_bind_sa(rctx, bind_pfx, &sb);
		}
	}

	// send response back
	strbuf_printf(&sb, "\n\t[%.6f] Sending reply\n", gettimestamp());
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);

    printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);

	printf("\t[%.6f] Returning\n\n", gettimestamp());
	return 0;
}

/** Socketconnect request function
 *  Is called upon each socketconnect request from a client
 *  Chooses a source prefix/address and then resolves the name
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketconnect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);

	printf("\n\tSocketconnect request: %s:%s\n\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	double timestamp = gettimestamp();
	_muacc_logtofile(logfile, "%.6f,,,,,,,,,,,,", timestamp);

	// Check if client has already chosen a source address to bind to
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;
		struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
		if (bind_pfx != NULL) {
			// Set DNS base to this prefix's
			rctx->evdns_base = bind_pfx->evdns_base;
			strbuf_printf(&sb, ", set DNS base. ");
		}
	}
	else
	{
		// search default address, and set it as bind_sa in the request context if found
		struct src_prefix_list *bind_pfx = get_default_prefix(rctx, &sb);
		if (bind_pfx != NULL) {
			set_bind_sa(rctx, bind_pfx, &sb);
			_muacc_logtofile(logfile, "%s_default\n", bind_pfx->if_name);

			// Set this prefix' evdns base for name resolution
			rctx->evdns_base = bind_pfx->evdns_base;
		}
		else
		{
			rctx->evdns_base = NULL;
		}
	}

    printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);

	rctx->action = muacc_act_socketconnect_resp;

	return resolve_name(rctx);
}

/** Socketchoose request function
 *  Is called upon each socketchoose request from a client
 *  Chooses from a set of existing sockets, or if none exists, does the same as socketconnect
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);

	printf("\n\tSocketchoose request: %s:%s\n\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	double timestamp = gettimestamp();
	_muacc_logtofile(logfile, "%.6f,", timestamp);
	GSList *spl = in4_enabled;
	while (spl != NULL)
	{
        struct src_prefix_list *cur = spl->data;
		int reuse = count_sockets_on_prefix(rctx->sockets, cur, logfile);
		_muacc_logtofile(logfile, "%d,", reuse);
		spl = spl->next;
	}
	_muacc_logtofile(logfile, ",,,,,,,,,");

	// Check if a set of existing sockets was supplied in the request
	if (rctx->sockets != NULL)
	{
		// First socket of set will be chosen
		printf("\tSuggest using socket %d\n", rctx->sockets->file);

		/* Provide the information to open a new similar socket, in case the suggested socket cannot be used */
		uuid_t context_id;
		__uuid_copy(context_id, rctx->ctx->ctxid);
		rctx->ctx = _muacc_clone_ctx(rctx->sockets->ctx);
		__uuid_copy(rctx->ctx->ctxid, context_id);

		_muacc_logtofile(logfile, "%d_reuse\n", rctx->sockets->file);
		strbuf_printf(&sb, "\n\tSending reply\n");
		_muacc_send_ctx_event(rctx, muacc_act_socketchoose_resp_existing);

		printf("%s\n\n", strbuf_export(&sb));
		strbuf_release(&sb);

		return 0;
	}
	else
	{
		printf("\tSocketchoose with empty set - trying to create new socket\n");

		if(rctx->ctx->bind_sa_req != NULL)
		{	// already bound
			strbuf_printf(&sb, "\tAlready bound to src=");
			_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);

			struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
			if (bind_pfx != NULL) {
				// Set DNS base to this prefix's
				rctx->evdns_base = bind_pfx->evdns_base;
				strbuf_printf(&sb, ", set DNS base. ");
			}
		}
		else
		{
			// search default address, and set it as bind_sa in the request context if found
			struct src_prefix_list *bind_pfx = get_default_prefix(rctx, &sb);
			if (bind_pfx != NULL) {
				set_bind_sa(rctx, bind_pfx, &sb);
				_muacc_logtofile(logfile, "%s_default\n", bind_pfx->if_name);

				// Set this prefix' evdns base for name resolution
				rctx->evdns_base = bind_pfx->evdns_base;
				strbuf_printf(&sb, ", set DNS base. ");
			}
			else
			{
				rctx->evdns_base = NULL;
			}
		}

		printf("%s\n\n", strbuf_export(&sb));
		strbuf_release(&sb);

		rctx->action = muacc_act_socketchoose_resp_new;

		return resolve_name(rctx);
	}
}

int on_new_subflow_request(mam_context_t *mctx, struct mptcp_flow_info *flow)
{
    return 0;
}
