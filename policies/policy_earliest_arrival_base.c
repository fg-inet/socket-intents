/** \file policy_earliest_arrival_base.c
 *  \brief Base functions for Earliest Arrival Policy. Leaves the actual prediction up to the policy implemented elsewhere.
 *
 *  \copyright Copyright 2013-2017 Philipp Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Behavior:
 *  Getaddrinfo   - Resolve names using the default dns_base from the MAM context
 *  Connect       - Choose the prefix with the shortest predicted completion time
 *  Socketconnect - Choose the prefix with the shortest predicted completion time and resolve name on it
 *  Socketchoose  - Choose a socket on the prefix with the shortest predicted completion time
 */

#include "policy_earliest_arrival_base.h"

/** List of enabled addresses for each address family */
GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

/** Initialize policy information for each prefix
 */
void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if (spl->policy_set_dict != NULL)
	{
		struct eafirst_info *new = malloc(sizeof(struct eafirst_info));
		memset(new, 0, sizeof(struct eafirst_info));
		new->is_default = 0;
		new->predicted_time = DBL_MAX;
		gpointer value = NULL;
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value )
			new->is_default = 1;
		spl->policy_info = new;
	}
	else
		spl->policy_info = NULL;
}

/** Helper to print additional information given to the policy
 */
void print_policy_info(void *policy_info)
{
	struct eafirst_info *info = policy_info;
	if (info->is_default)
		printf(" (default)");
}

void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if (spl->policy_info != NULL)
	{
		free(spl->policy_info);
	}

	spl->policy_info = NULL;
}

/** Returns the default prefix, if any exists, otherwise NULL
 */
struct src_prefix_list *get_default_prefix(GSList *spl, request_context_t *rctx, strbuf_t *sb)
{
	if (spl == NULL)
	{
		// If address family is specified, only look in its list, else look in both (v4 first)
		if (rctx->ctx->domain == AF_INET)
			spl = in4_enabled;
		else if (rctx->ctx->domain == AF_INET6)
			spl = in6_enabled;
		else
			spl = g_slist_concat(in4_enabled, in6_enabled);
	}

	// Go through list of src prefixes
	while (spl != NULL)
	{
		// Look at per-prefix policy information
		struct src_prefix_list *cur = spl->data;
		struct eafirst_info *pfxinfo = cur->policy_info;
		if (pfxinfo != NULL && pfxinfo->is_default)
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

struct src_prefix_list *get_fastest_prefix(GSList *spl)
{
	struct src_prefix_list *cur = NULL;
	struct src_prefix_list *fastest = NULL;
	double min_completion_time = DBL_MAX;

	while (spl != NULL)
	{
		cur = spl->data;
		if (cur->policy_info != NULL && ((struct eafirst_info *)cur->policy_info)->predicted_time < min_completion_time)
		{
			fastest = cur;
			min_completion_time = ((struct eafirst_info *)cur->policy_info)->predicted_time;
		}
		spl = spl->next;
	}
	return fastest;
}

void set_reuse_count (GSList *spl, request_context_t *rctx)
{
	while (spl != NULL) {
		struct src_prefix_list *cur = spl->data;
		struct eafirst_info *pfxinfo = cur->policy_info;

		// Check if there is a socket to reuse on this prefix
		pfxinfo->reuse = count_sockets_on_prefix(rctx->sockets, cur, logfile);
		_muacc_logtofile(logfile, "%d,", pfxinfo->reuse);
		spl = spl->next;
    }
}

/** Get best source prefix:
 *  If filesize is not known, use default prefix if available
 *  If filesize is known, call get_best_prefix()
 *  If prediction fails, use the default prefix if available
 */
struct src_prefix_list *get_src_prefix(request_context_t *rctx, strbuf_t *sb)
{
	double timestamp = gettimestamp();
	_muacc_logtofile(logfile, "%.6f,", timestamp);
	GSList *spl = NULL;

	int filesize = 0;
	socklen_t fslen = sizeof(int);

	struct src_prefix_list *chosenpfx = NULL;

	if (rctx->ctx->domain == AF_INET)
		spl = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		spl = in6_enabled;
	else
		spl = g_slist_concat(in4_enabled, in6_enabled);

	// Check for Filesize Intent in request context
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &filesize) != 0)
	{
		strbuf_printf(sb, "\tNo filesize given - cannot predict completion time!\n");
		_muacc_logtofile(logfile, ",");
		set_reuse_count(spl, rctx);

		_muacc_logtofile(logfile, ",,,");
		chosenpfx = get_default_prefix(spl, rctx, sb);
		_muacc_logtofile(logfile, "%s_default\n", chosenpfx->if_name);
	}
	else
	{
		_muacc_logtofile(logfile, "%d,", filesize);
		set_reuse_count(spl, rctx);

		chosenpfx = get_best_prefix(spl, filesize, rctx, logfile, sb);
	}

	return chosenpfx;
}

/** Initializer function (mandatory)
 *  Is called once the policy is loaded and every time it is reloaded
 *  Typically sets the policy_info and initializes the lists of candidate addresses
 */
int init(mam_context_t *mctx)
{
	printf("Policy module \"earliest arrival\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	logfile = g_hash_table_lookup(mctx->policy_set_dict, "logfile");
	if (logfile != NULL)
	{
		printf("\nLogging to %s\n", logfile);
	}

	printf("\nPolicy module \"earliest arrival\" has been loaded.\n");
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

	printf("Policy earliest arrival cleaned up.\n");
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
	    strbuf_printf(&sb, "\tError resolving: %s -> %s\n", rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
		rctx->action = muacc_error_resolve;
	}
	else
	{
		// Successfully resolved name
		strbuf_printf(&sb, "\tGot resolver response for %s %s\n",
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

		evutil_freeaddrinfo(addr);
	}

	// send reply to client
	strbuf_printf(&sb, "\n\tSending reply");
	_muacc_send_ctx_event(rctx, rctx->action);

    printf("%s\n\n", strbuf_export(&sb));
    int ret = strbuf_release(&sb);
    if (ret > 0) {
        fprintf(stderr, "Strbuf could not be freed! %d\n", ret);
    }
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

	strbuf_printf(&sb, "\tResolving: %s:%s with hint: ", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
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
    int ret = strbuf_release(&sb);
    if (ret > 0) {
        fprintf(stderr, "Strbuf could not be freed! %d\n", ret);
    }

	return 0;
}

/** Resolve request 
 *  Resolve name using default dns base
 */
int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("\n\tResolve request: %s:%s\n\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	rctx->evdns_base = rctx->mctx->evdns_default_base;
	rctx->action = muacc_act_getaddrinfo_resolve_resp;

	return resolve_name(rctx);
}

/** Connect request 
 *  Choose source prefix
 */
int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\n\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);
	strbuf_printf(&sb, "\n\n");

	// Check if client has already chosen a source address to bind to
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;
	}
	else
	{
		// search preferred source prefix, and set it as bind_sa in the request context if found
		struct src_prefix_list *bind_pfx = get_src_prefix(rctx, &sb);
		if (bind_pfx != NULL) {
			choose_this_prefix(rctx, bind_pfx, &sb);
		}
	}

	// send response back
	strbuf_printf(&sb, "\n\tSending reply");
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);

    printf("%s\n\n", strbuf_export(&sb));
    int ret = strbuf_release(&sb);
    if (ret > 0) {
        fprintf(stderr, "Strbuf could not be freed! %d\n", ret);
    }

	return 0;
}

/** Socketconnect
 *  Choose best prefix (fastest, if not available: default), then resolves name on this prefix
 */
int on_socketconnect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);

	printf("\n\tSocketconnect request: %s:%s\n\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

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
		struct src_prefix_list *bind_pfx = get_src_prefix(rctx, &sb);
		if (bind_pfx != NULL) {
			choose_this_prefix(rctx, bind_pfx, &sb);

			// Set this prefix' evdns base for name resolution
			rctx->evdns_base = bind_pfx->evdns_base;
		}
		else
		{
			rctx->evdns_base = NULL;
		}
	}

    printf("%s\n\n", strbuf_export(&sb));
	int ret = strbuf_release(&sb);
    if (ret > 0) {
        fprintf(stderr, "Strbuf could not be freed! %d\n", ret);
    }

	rctx->action = muacc_act_socketconnect_resp;

	return resolve_name(rctx);
}

/** Socketchoose
 *  Select fastest source prefix, then choose a socket on this prefix.
 *  If this fails, resolve name and suggest client to open a new socket
 */
int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);

	printf("\n\tSocketchoose request: %s:%s ", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
    if (rctx->sockets != NULL)
    {
        printf("with socketset: ");
        print_sockets(rctx->sockets);
    }
    printf("\n\n");
	
	struct src_prefix_list *bind_pfx = NULL;

	// Check if source address was already chosen
	if(rctx->ctx->bind_sa_req == NULL)
	{
		// No source address chosen yet - choose best prefix
		bind_pfx = get_src_prefix(rctx, &sb);
		if (bind_pfx != NULL) {
			choose_this_prefix(rctx, bind_pfx, &sb);

			// Set this prefix' evdns base for name resolution
			rctx->evdns_base = bind_pfx->evdns_base;
		}
	}
	else
	{
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
	}

	// Attempt to suggest an existing socket on the preferred prefix
	if (bind_pfx != NULL && rctx->sockets != NULL)
	{
		strbuf_printf(&sb, "\n\tPicking a socket on prefix with address ");
		_muacc_print_sockaddr(&sb, bind_pfx->if_addrs->addr, bind_pfx->if_addrs->addr_len);
		strbuf_printf(&sb, "\n");

		// Filter the request context's socket list, only leaving sockets on our preferred prefix
		pick_sockets_on_prefix(rctx, bind_pfx);

		if (rctx-> sockets != NULL)
		{
			// At least one matching socket was found
			strbuf_printf(&sb, "\tFirst candidate socket: %d\n", rctx->sockets->file);

			/* Provide the information to open a new similar socket, in case the suggested socket cannot be used */
			uuid_t context_id;
			__uuid_copy(context_id, rctx->ctx->ctxid);
			_muacc_free_ctx(rctx->ctx);
			rctx->ctx = _muacc_clone_ctx(rctx->sockets->ctx);
			__uuid_copy(rctx->ctx->ctxid, context_id);

			printf("%s\n\n", strbuf_export(&sb));
			int ret = strbuf_release(&sb);
            if (ret > 0) {
                fprintf(stderr, "Strbuf could not be freed! %d\n", ret);
            }

			// Send reply back to client
			_muacc_send_ctx_event(rctx, muacc_act_socketchoose_resp_existing);

			return 0;
		}
		else
		{
			strbuf_printf(&sb, "\tDid not find a socket on this prefix\n");
		}
	}
	else
	{
		strbuf_printf(&sb, "\tSocketchoose with empty set or no preferred prefix found\n");
	}
		
	strbuf_printf(&sb, "\tSocketchoose - suggesting creation of a new socket, resolving %s\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname));

	rctx->action = muacc_act_socketchoose_resp_new;

	printf("%s\n\n", strbuf_export(&sb));
	int ret = strbuf_release(&sb);
    if (ret > 0) {
        fprintf(stderr, "Strbuf could not be freed! %d\n", ret);
    }

	return resolve_name(rctx);
}


int on_new_subflow_request(mam_context_t *mctx, struct mptcp_flow_info *flow)
{
    return 0;
}
