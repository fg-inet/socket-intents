/** \file policy_earliest_arrival.c
 *  \brief Policy that calculates the predicted completion time for an object on all prefixes and selects the fastest
 *
 *  \copyright Copyright 2013-2016 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Behavior:
 *  Getaddrinfo   - Resolve names using the default dns_base from the MAM context
 *  Connect       - Choose the prefix with the shortest predicted completion time
 *  Socketconnect - Choose the prefix with the shortest predicted completion time and resolve name on it
 *  Socketchoose  - Choose a socket on the prefix with the shortest predicted completion time
 */

#include "policy.h"
#include "policy_util.h"
#include <time.h>

/** Policy-specific per-prefix data structure that contains additional information */
struct eafirst_info {
	int is_default;              /** 1 if the prefix has been specified as default in the config file */
	double predicted_time;       /** estimated completion time for current object on this prefix */
	double scheduled_connections_penalty; /** Counts scheduled connections */
	double connections_rate_timestamp_sec; /** Timestamp when counter of scheduled connections was last updated */
	double connections_rate_timestamp_usec; /** Timestamp when counter of scheduled connections was last updated */
};

void check_timestamps(struct src_prefix_list *pfx, strbuf_t *sb);

double get_srtt(struct src_prefix_list *pfx, strbuf_t *sb);
double get_max_rate(struct src_prefix_list *pfx, strbuf_t *sb);
double get_rate(struct src_prefix_list *pfx, strbuf_t *sb);
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb);
double predict_completion_time(struct src_prefix_list *pfx, int filesize, int reuse, strbuf_t *sb);

struct src_prefix_list *get_src_prefix(request_context_t *rctx, int reuse, strbuf_t *sb);
struct src_prefix_list *get_fastest_prefix(GSList *spl);
struct src_prefix_list *get_default_prefix(request_context_t *rctx, strbuf_t *sb);

int resolve_name(request_context_t *rctx);

static const char *logfile = NULL;

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
		new->is_default = 0;
		new->predicted_time = DBL_MAX;
		new->scheduled_connections_penalty = 0;
		struct timeval current_time;
		gettimeofday(&current_time, NULL);
		new->connections_rate_timestamp_sec = current_time.tv_sec;
		new->connections_rate_timestamp_usec = current_time.tv_usec;
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
struct src_prefix_list *get_default_prefix(request_context_t *rctx, strbuf_t *sb)
{
	GSList *spl = NULL;
	struct src_prefix_list *cur = NULL;
	struct eafirst_info *info = NULL;

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
		info = (struct eafirst_info *)cur->policy_info;
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

/* Look up a smoothed RTT value on a prefix */
double get_srtt(struct src_prefix_list *pfx, strbuf_t *sb)
{
	if (pfx == NULL)
		return 0;

	double min_srtt = 0;
	gpointer value = NULL;
	if (((value = g_hash_table_lookup(pfx->policy_set_dict, "min_srtt")) != NULL) && value )
		min_srtt = strtod((char *)value, NULL);

	if (min_srtt < EPSILON)
	{
		// If not found or zero: Return
		strbuf_printf(sb, "\t\tMinimum RTT:   N/A,   ");
		return 0;
	}

	strbuf_printf(sb, "\t\tMinimum RTT: %.2f ms, ", min_srtt);
	return min_srtt;
}

/* Look up a value for maximum download rate on a prefix */
double get_max_rate(struct src_prefix_list *pfx, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	/* Smoothed rates are not used for now!
	// Look up smoothed maximum download rate first
	double *download_max_rate = lookup_prefix_info(pfx, "download_max_srate");

	if (download_max_rate == NULL || *download_max_rate < EPSILON)
		// If not found or zero: look up maximum download rate (non-smoothoed)
		download_max_rate = lookup_prefix_info(pfx, "download_max_rate");
	*/

	double download_max_rate = 0;
	gpointer value = NULL;
	if (((value = g_hash_table_lookup(pfx->policy_set_dict, "download_max_rate")) != NULL) && value )
		download_max_rate = strtod((char *)value, NULL);


	/*if (download_max_rate == NULL)
	{
		// If still not found or zero: Return
		strbuf_printf(sb, "download max rate:   N/A,   ");
		return -1;
	}*/

	strbuf_printf(sb, "download max rate: %.2f, ", download_max_rate);

	return download_max_rate;
}

/* Look up a value for current download rate on a prefix */
double get_rate(struct src_prefix_list *pfx, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	/* Smoothed rates are not used for now!
	// Look up smoothed download rate
	double *download_rate = lookup_prefix_info(pfx, "download_srate");

	if (download_rate == NULL || *download_rate < EPSILON)
		// If not found or zero: take download rate (non-smoothoed)
		download_rate = lookup_prefix_info(pfx, "download_rate");
	*/
	double *download_rate = lookup_prefix_info(pfx, "download_rate");

	if (download_rate == NULL)
	{
		// If still not found: Return
		strbuf_printf(sb, "download rate:   N/A,   ");
		return -1;
	}

	strbuf_printf(sb, "download rate: %.2f, ", *download_rate);

	return *download_rate;
}

/** Check if timestamp of the information on scheduled connections is older than last rate measurement
 *  If yes, reset scheduled connection count
 */
void check_timestamps(struct src_prefix_list *pfx, strbuf_t *sb)
{
	double *conns_timestamp_sec = &((struct eafirst_info *)pfx->policy_info)->connections_rate_timestamp_sec;
	double *conns_timestamp_usec = &((struct eafirst_info *)pfx->policy_info)->connections_rate_timestamp_usec;
	double *measurement_timestamp_sec = lookup_prefix_info(pfx, "rate_timestamp_sec");
	double *measurement_timestamp_usec = lookup_prefix_info(pfx, "rate_timestamp_usec");

	strbuf_printf(sb, "\n\t\t---- measure timestamp: %.0f.%.0f, conns_timestamp: %.0f.%.0f ", *measurement_timestamp_sec, *measurement_timestamp_usec, *conns_timestamp_sec, *conns_timestamp_usec);
	if (*measurement_timestamp_sec > *conns_timestamp_sec || (*measurement_timestamp_sec >= *conns_timestamp_sec && *measurement_timestamp_usec > *conns_timestamp_usec))
	{
		// Rate measurement is newer than timestamp on scheduled connections counter
		((struct eafirst_info *)pfx->policy_info)->scheduled_connections_penalty = 0;
		strbuf_printf(sb, " - resetting\n", *measurement_timestamp_sec, *measurement_timestamp_usec, *conns_timestamp_sec, *conns_timestamp_usec);

		struct timeval current_time;
		gettimeofday(&current_time, NULL);
		*conns_timestamp_usec = current_time.tv_usec;
		*conns_timestamp_sec = current_time.tv_sec;
	}
	else
	{
		strbuf_printf(sb, " \n", *measurement_timestamp_sec, *measurement_timestamp_usec, *conns_timestamp_sec, *conns_timestamp_usec);
	}
}

/* Compute free capacity on a prefix */
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	// Compute free capacity on the link
	double free_capacity = max_rate - rate;

	check_timestamps(pfx, sb);

	double conns_penalty = ((struct eafirst_info *)pfx->policy_info)->scheduled_connections_penalty;

	if (conns_penalty > 0)
	{
		strbuf_printf(sb, "\t\t (penalty %.3f ) ", conns_penalty);
		free_capacity = free_capacity / (conns_penalty + 1);
	}

	if (free_capacity < EPSILON)
	{
		strbuf_printf(sb, " Got invalid free capacity: %f\n", free_capacity);
		return -1;
	}

	strbuf_printf(sb, "free capacity: %.2f\n", free_capacity);

	return free_capacity;
}

/* Estimate completion time of an object of a given file size on this prefix */
double predict_completion_time(struct src_prefix_list *pfx, int filesize, int reuse, strbuf_t *sb)
{
	if (pfx == NULL)
		return 0;

	strbuf_printf(sb, "\tPredicting completion time for new object (%d bytes) on %s %s\n", filesize, pfx->if_name, (reuse) ? "(connection reuse)" : "");

	double completion_time = DBL_MAX;

	double srtt = get_srtt(pfx, sb);
	double max_rate = get_max_rate(pfx, sb);
	double rate = get_rate(pfx, sb);
	double free_capacity = get_capacity(pfx, max_rate, rate, sb);

	_muacc_logtofile(logfile, "%f,%f,%f,%f,", srtt, max_rate, rate, free_capacity);

	if (srtt > EPSILON && free_capacity > EPSILON)
	{
		if (reuse)
		{
			// Predict completion time for reusing a connection
			completion_time = srtt + 1000 * (filesize / free_capacity);
		}
		else
		{
			// Compute prediction of completion time
			completion_time = 2 * srtt + 1000 * (filesize / free_capacity);
		}

		strbuf_printf(sb, "\t\tEstimated completion time is %.2f ms\n", completion_time);
		_muacc_logtofile(logfile, "%f,", completion_time);
	}
	else
	{
		// Not all metrics found - cannot compute completion time
		strbuf_printf(sb, "\t\tCannot compute completion time!\n");
		_muacc_logtofile(logfile, "0.0,", completion_time);
	}

	return completion_time;
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

/** Get best source prefix:
 *  If filesize is not known, use default prefix if available
 *  If filesize is known, predict completion time on each possible source prefix, and choose the fastest one
 *  If prediction fails, use the default prefix if available
 */
struct src_prefix_list *get_src_prefix(request_context_t *rctx, int reuse, strbuf_t *sb)
{
	int timestamp = (int)time(NULL);

	char uuid_str[37];
	__uuid_unparse_lower(rctx->ctx->ctxid, uuid_str);
	_muacc_logtofile(logfile, "%d,%s,", timestamp, uuid_str);
	GSList *spl = NULL;
	struct src_prefix_list *cur = NULL;

	int filesize = 0;
	socklen_t fslen = sizeof(int);

	struct src_prefix_list *chosenpfx = NULL;

	// Check for Filesize Intent in request context
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &filesize) != 0)
	{
		strbuf_printf(sb, "\tNo filesize given - cannot predict completion time!\n");
		_muacc_logtofile(logfile, "0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,");
		chosenpfx = get_default_prefix(rctx, sb);
		_muacc_logtofile(logfile, "%s_default\n", chosenpfx->if_name);
	}
	else
	{
		_muacc_logtofile(logfile, "%d,", filesize);

		// Filesize Intent given -- get list of possible source prefixes
		if (rctx->ctx->domain == AF_INET)
			spl = in4_enabled;
		else if (rctx->ctx->domain == AF_INET6)
			spl = in6_enabled;
		else
			spl = g_slist_concat(in4_enabled, in6_enabled);

		// Save prefix list for later use
		GSList *spl2 = spl;

		// Go through list of possible source prefixes
		while (spl != NULL)
		{
			cur = spl->data;

			// Check if there is a socket to reuse on this prefix - if not, predict for new connection
			reuse = is_there_a_socket_on_prefix(rctx->sockets, cur);

			// Predict completion time on this prefix
			((struct eafirst_info *)cur->policy_info)->predicted_time = predict_completion_time(cur, filesize, reuse, sb);

			spl = spl->next;
		}

		// Get prefix with shortest predicted completion time
		chosenpfx = get_fastest_prefix(spl2);

		// Check if we have a fastest prefix with a reasonable completion time
		if (chosenpfx != NULL && chosenpfx->policy_info != NULL)
		{
			double min_completion_time = ((struct eafirst_info *)chosenpfx->policy_info)->predicted_time;
			if (min_completion_time > EPSILON && min_completion_time < DBL_MAX)
			{
				// Set source prefix to the fastest prefix
				strbuf_printf(sb, "\tFastest prefix is on %s (%.2f ms)", chosenpfx->if_name, min_completion_time);
				_muacc_logtofile(logfile, "%s_fastest\n", chosenpfx->if_name);

				double penalty = 1;
				double *callback_duration = lookup_prefix_info(chosenpfx, "callback_duration_rate");
				if (min_completion_time < (*callback_duration * 1000)) {
					penalty = min_completion_time / (*callback_duration * 1000);
				}

				// Increment counter of scheduled connections for this prefix and set timestamp
				struct timeval current_time;
				gettimeofday(&current_time, NULL);
				((struct eafirst_info *)chosenpfx->policy_info)->scheduled_connections_penalty += penalty;
				((struct eafirst_info *)chosenpfx->policy_info)->connections_rate_timestamp_sec = current_time.tv_sec;
				((struct eafirst_info *)chosenpfx->policy_info)->connections_rate_timestamp_usec = current_time.tv_usec;
				strbuf_printf(sb, " (penalty += %.3f at %.0f.%.0f )\n", penalty, (double) current_time.tv_sec, (double) current_time.tv_usec);
			}
			else
			{
				strbuf_printf(sb, "\tGot completion time of %.2f ms on %s - not taking it\n", min_completion_time, chosenpfx->if_name);
				chosenpfx = get_default_prefix(rctx, sb);
				_muacc_logtofile(logfile, "%s_default\n", chosenpfx->if_name);
			}	
		}
		else
		{
			strbuf_printf(sb, "\tCould not determine fastest prefix\n");
			chosenpfx = get_default_prefix(rctx, sb);
			_muacc_logtofile(logfile, "%s_default\n", chosenpfx->if_name);
		}

	}

	return chosenpfx;
}

/** Initializer function (mandatory)
 *  Is called once the policy is loaded and every time it is reloaded
 *  Typically sets the policy_info and initializes the lists of candidate addresses
 */
int init(mam_context_t *mctx)
{
	printf("Policy module \"earliest arrival (static)\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	logfile = g_hash_table_lookup(mctx->policy_set_dict, "logfile");
	if (logfile != NULL)
	{
		printf("\nLogging to %s\n", logfile);
	}

	printf("\nPolicy module \"earliest arrival (static)\" has been loaded.\n");
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

	printf("Policy earliest arrival (validation) cleaned up.\n");
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
    strbuf_release(&sb);
}

/* Helper function that issues a DNS request
   and registers the callback resolve_request_result */
int resolve_name(request_context_t *rctx)
{
	strbuf_t sb;
	strbuf_init(&sb);

    struct evdns_getaddrinfo_request *req;

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
    req = evdns_getaddrinfo(
    		evdns_base,
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result,
			rctx);

    printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);

	/* If function returned immediately, request failed */
    if (req == NULL) {
		printf("\tRequest failed. Sending reply.\n");
		_muacc_send_ctx_event(rctx, muacc_error_resolve);
		return -1;
	}
	else {
		return 0;
	}
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
		struct src_prefix_list *bind_pfx = get_src_prefix(rctx, 0, &sb);
		if (bind_pfx != NULL) {
			set_bind_sa(rctx, bind_pfx, &sb);
		}
	}

	// send response back
	strbuf_printf(&sb, "\n\tSending reply");
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);

    printf("%s\n\n", strbuf_export(&sb));
    strbuf_release(&sb);

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
		struct src_prefix_list *bind_pfx = get_src_prefix(rctx, 0, &sb);
		if (bind_pfx != NULL) {
			set_bind_sa(rctx, bind_pfx, &sb);

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

/** Socketchoose
 *  Select fastest source prefix, then choose a socket on this prefix.
 *  If this fails, resolve name and suggest client to open a new socket
 */
int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);

	printf("\n\tSocketchoose request: %s:%s\n\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	
	struct src_prefix_list *bind_pfx = NULL;

	// Check if source address was already chosen
	if(rctx->ctx->bind_sa_req == NULL)
	{
		// No source address chosen yet - choose best prefix
		bind_pfx = get_src_prefix(rctx, 1, &sb);
		if (bind_pfx != NULL) {
			set_bind_sa(rctx, bind_pfx, &sb);

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
			rctx->ctx = _muacc_clone_ctx(rctx->sockets->ctx);
			__uuid_copy(rctx->ctx->ctxid, context_id);

			printf("%s\n\n", strbuf_export(&sb));
			strbuf_release(&sb);

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
	strbuf_release(&sb);

	return resolve_name(rctx);
}
