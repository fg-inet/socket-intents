/** \file policy_filesize.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "policy.h"
#include "policy_util.h"

/* Per-prefix info about filesize range */
struct filesize_info {
	int 		minfilesize;
	int			maxfilesize;
	int			is_default;
};

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

char addr_str[INET6_ADDRSTRLEN];	/** string for debug / error printing */

void print_policy_info(void *policy_info)
{
	struct filesize_info *info = policy_info;
	printf("\t(for filesize %6d =< n =< %6d)", info->minfilesize, info->maxfilesize);
	if (info->is_default)
		printf(" (default)");
}

void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct filesize_info *new = malloc(sizeof(struct filesize_info));
	memset(new, 0, sizeof(struct filesize_info));
	new->maxfilesize = INT_MAX;

	if (spl->policy_set_dict != NULL)
	{
		/* Set filesize from config file */
		gpointer value = NULL;
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "minfilesize")) != NULL)
			new->minfilesize = atoi(value);
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "maxfilesize")) != NULL)
			new->maxfilesize = atoi(value);
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value)
            new->is_default = 1;
	}

	spl->policy_info = (void *) new;
}

void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if(spl->policy_info != NULL)
		free(spl->policy_info);
}

static void set_sa_for_filesize(request_context_t *rctx, int filesize, strbuf_t sb)
{
	GSList *elem = NULL;
	struct src_prefix_list *spl = NULL;
	struct src_prefix_list *defaultaddr = NULL;
	struct evdns_base      *defaultevdns_base = NULL;

	if (rctx->ctx->domain == AF_INET)
		elem = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		elem = in6_enabled;

	while (elem != NULL)
	{
		spl = elem->data;
		struct filesize_info *info = spl->policy_info;

		if (info->minfilesize <= filesize && info->maxfilesize >= filesize)
		{
			/* Filesizes falls within this prefixes' configuration: Set source address */
			set_bind_sa(rctx, spl, &sb);
			strbuf_printf(&sb, " for filesize %d", filesize);
			/* copy evdns base of spl */
			rctx->evdns_base = ( spl->evdns_base != NULL ?
				spl->evdns_base :
			       	rctx->mctx->evdns_default_base );
				
			break;
		}
		if (info->is_default)
		{
			/* This prefix is default. Store it for eventual fallback. */
			defaultaddr = spl;
			defaultevdns_base = ( spl->evdns_base != NULL ?
				spl->evdns_base :
			       	rctx->mctx->evdns_default_base );
		}
		elem = elem->next;
	}

	if (elem == NULL)
	{
		if (filesize > 0)
			strbuf_printf(&sb, "\n\tCould not find suitable address for filesize %d", filesize);
		if (defaultaddr != NULL)
		{
			set_bind_sa(rctx, defaultaddr, &sb);
			strbuf_printf(&sb, " (default)");
		}
	}
}

int init(mam_context_t *mctx)
{
	printf("\nPolicy module \"filesize\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	printf("\nPolicy module \"filesize\" has been loaded.\n");

	return 0;
}

int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);
	printf("\nPolicy module \"filesize\" cleaned up.\n");
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
	strbuf_t sb;
	strbuf_init(&sb);
	
	strbuf_printf(&sb, "\tResolve request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	int fs = 0;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) != 0)
	{
		// no filesize given - Setting default address
		strbuf_printf(&sb, "\n\t\tNo filesize intent given - delaying and using default evdns_base.");
		rctx->evdns_base = rctx->mctx->evdns_default_base;
	}	
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\n\t\tAlready bound - not touching evdns_base.");
	}
	else
	{
		// set sa - implicitly sets rctx->evdns_base
		set_sa_for_filesize(rctx, fs, sb);
	}

	/* Try to resolve this request using asynchronous lookup */
	assert(rctx->evdns_base!=NULL);
	req = evdns_getaddrinfo(
		rctx->evdns_base,
		rctx->ctx->remote_hostname,
		rctx->ctx->remote_service,
		rctx->ctx->remote_addrinfo_hint,
		&resolve_request_result,
		rctx);
	strbuf_printf(&sb, " - Sending request to default nameserver\n");
    if (req == NULL) {
		/* returned immediately  */
		strbuf_printf(&sb, "\tRequest failed.\n");
	}
	printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}


int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	int fs = 0;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) != 0)
	{
		// no filesize given - Setting default address
		strbuf_printf(&sb, "\n\tNo filesize intent given - Using default if applicable.");
		set_sa_for_filesize(rctx, -1, sb);
	}
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\t\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}
	else
	{
		set_sa_for_filesize(rctx, fs, sb);
	}

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
	}
	
	strbuf_printf(&sb, "\tSending reply\n");
	_muacc_send_ctx_event(rctx, action);

    printf("%s\n\n", strbuf_export(&sb));
    strbuf_release(&sb);
}



int _on_socketconnect_or_choose_new(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;
	strbuf_t sb;
	strbuf_init(&sb);

	int fs = 0;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) != 0)
	{
		// no filesize given - Setting default address
		strbuf_printf(&sb, "\n\t\tNo filesize intent given - delaying and using default evdns_base.");
		rctx->evdns_base = rctx->mctx->evdns_default_base;
	}	
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\n\t\tAlready bound - not touching evdns_base.");
	}
	else
	{
		// set sa - implicitly sets rctx->evdns_base
		set_sa_for_filesize(rctx, fs, sb);
	}
	
	/* Try to resolve this request using asynchronous lookup */
	assert(rctx->evdns_base!=NULL);

    	req = evdns_getaddrinfo(
		rctx->evdns_base,
		rctx->ctx->remote_hostname,
		rctx->ctx->remote_service,
		rctx->ctx->remote_addrinfo_hint,
		&resolve_request_result_connect,
		rctx);
	if (req == NULL) {
		/* returned immediately */
		strbuf_printf(&sb, "\tRequest failed.\n");
	}
	printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}

/** Socketconnect request function
 *  Is called upon each socketconnect request from a client
 *  Performs name resolution and then chooses a local address
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketconnect_request(request_context_t *rctx, struct event_base *base)
{	
	printf("\tSocketconnect request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	return _on_socketconnect_or_choose_new(rctx, base);
}

/** Socketchoose request function
 *  Is called upon each socketchoose request from a client
 *  Chooses from a set of existing sockets
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{	
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
		
		return 0;
		
	}
	else
	{
		printf("\tSocketchoose with empty set - trying to create new socket, resolving %s\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname));
		return _on_socketconnect_or_choose_new(rctx, base);
	}

}
