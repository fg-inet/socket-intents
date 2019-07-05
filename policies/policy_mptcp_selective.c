/** \file policy_mptcp_selective.c
 *  \brief Use MPTCP, start on lower latency interface
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Policy_info: Data structure for each prefix. In this policy, specifies default interface
 *              The default interface is only used if we can't find a low SRTT interface.

 *  Behavior:
 *  Resolve Request - Resolve names using the default dns_base from the MAM context
 *  Connect         - Choose the lower latency prefix if available, enable MPTCP
 *  Socketconnect   - Choose the lower latency prefix if available, resolve name on its dns_base if available, enable MPTCP
 *  Socketchoose    - From list of available sockets, choose first one, else do same as socketconnect, enable MPTCP
 */

#include "policy.h"
#include "policy_util.h"


#define LATENCY_ESTIMATE "srtt_minimum_recent"
#define MAX_CAPACITY_ESTIMATE "download_sma_max_mid"
#define MAX_CAPACITY_ESTIMATE_FALLBACK "download_sma_max_long"

#define SEGMENT_DURATION 4

/** Policy-specific per-prefix data structure that contains additional information */
struct sample_info {
	int is_default;
    int reuse;
    int count;
};

/** List of enabled addresses for each address family */
GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

static const char *logfile = NULL;

struct src_prefix_list *get_default_prefix(request_context_t *rctx, strbuf_t *sb);
int resolve_name(request_context_t *rctx);

struct src_prefix_list *select_pfx_or_mptcp(request_context_t *rctx, GSList *spl, intent_category_t category, int filesize, int duration, strbuf_t *sb);
void increment_non_chosen(GSList *spl, struct src_prefix_list *chosen, int mptcp_used);
struct src_prefix_list *get_not_recently_picked(GSList *spl, strbuf_t *sb);
void set_to_zero(GSList *spl);

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

/** get_not_recently_picked
 *  -- get the network with higher count (without resetting it)
 */
struct src_prefix_list *get_not_recently_picked(GSList *spl, strbuf_t *sb)
{
	struct src_prefix_list *cur = NULL;
	struct sample_info *info = NULL;
    int not_picked_max = 0;
    struct src_prefix_list *candidate = NULL;

	// Go through list of src prefixes
	while (spl != NULL)
	{
		// Look at per-prefix policy information
		cur = spl->data;
		info = (struct sample_info *)cur->policy_info;
		if (info != NULL && info->count > not_picked_max)
		{
		   candidate = cur;
		   not_picked_max = info->count;
		}
		spl = spl->next;
	}

	return(candidate);
}

void increment_non_chosen(GSList *spl, struct src_prefix_list *chosen, int mptcp_used)
{
	// Go through list of possible source prefixes
	while (spl != NULL)
	{
		struct src_prefix_list *cur = spl->data;
        struct sample_info *pfxinfo = cur->policy_info;
        if (spl->data != chosen && !mptcp_used) {
            pfxinfo->count++;
        }
		spl = spl->next;
	}
}

void set_to_zero(GSList *spl)
{
	// Go through list of possible source prefixes
	while (spl != NULL)
	{
		struct src_prefix_list *cur = spl->data;
        struct sample_info *pfxinfo = cur->policy_info;
        pfxinfo->count = 0;
		spl = spl->next;
	}
}

/** Depending on intents, select prefix and/or enable MPTCP:
 *  For queries, pick low latency interface
 *  For bulk, either enable MPTCP if sufficient capacity, or only use
 *  high capacity interface if no sufficient capacity
 */
struct src_prefix_list *select_pfx_or_mptcp(request_context_t *rctx, GSList *spl, intent_category_t category, int filesize, int duration, strbuf_t *sb) {
    strbuf_printf(sb, "\tselecting a prefix\n");
    struct src_prefix_list *chosenpfx = NULL;
    int enabled = 1; // Needed in case we enable MPTCP

    if (category == INTENT_QUERY) {
        // Query -- choose lowest latency prefix
        strbuf_printf(sb, "\tQuery - looking for lowest latency interface %s", LATENCY_ESTIMATE, (chosenpfx == NULL) ? "none" : chosenpfx->if_name);
        chosenpfx = get_lowest_srtt_pfx(spl, LATENCY_ESTIMATE, sb);
        strbuf_printf(sb, "\n\tLowest latency (%s) interface: %s (and no MPTCP)\n", LATENCY_ESTIMATE, (chosenpfx == NULL) ? "none" : chosenpfx->if_name);
        if (chosenpfx != NULL) {
            _muacc_logtofile(logfile, "%s,lowlatency\n", chosenpfx->if_name);
        }
    } else if (category == INTENT_CONTROLTRAFFIC) {
        // "Control traffic" is our audio stream -- get not recently picked network
        chosenpfx = get_not_recently_picked(spl, sb);
        strbuf_printf(sb, "\tNot recently picked (%d) interface: %s\n", (chosenpfx == NULL) ? -1 : ((struct sample_info *)chosenpfx->policy_info)->count, (chosenpfx == NULL) ? "none" : chosenpfx->if_name);
        /*if (chosenpfx != NULL) {
            _muacc_logtofile(logfile, "%s,control\n", chosenpfx->if_name);
        }*/

    } else if (category == INTENT_BULKTRANSFER) {
        strbuf_printf(sb, "\tBulk - looking if there is sufficient capacity on the low capacity interface\n", MAX_CAPACITY_ESTIMATE, (chosenpfx == NULL) ? "none" : chosenpfx->if_name);
        // Bulk transfer - see if there is sufficient capacity for MPTCP
        // or otherwise only use higher capacity interface
        struct src_prefix_list *lower_srtt_prefix = get_lowest_srtt_pfx(spl, LATENCY_ESTIMATE, sb);
        struct src_prefix_list *lower_capacity_prefix = get_lowest_capacity_pfx(spl, MAX_CAPACITY_ESTIMATE, MAX_CAPACITY_ESTIMATE_FALLBACK, sb);
        strbuf_printf(sb, "\n\tLow latency: %s, low capacity: %s\n", (lower_srtt_prefix == NULL) ? "none" : lower_srtt_prefix->if_name, (lower_capacity_prefix == NULL) ? "none" : lower_capacity_prefix->if_name);
        /*if (lower_srtt_prefix != lower_capacity_prefix) {
            strbuf_printf(sb, "\tLowest latency (%s) interface: %s and lowest capacity (%s) interface: %s\n", LATENCY_ESTIMATE, (lower_srtt_prefix == NULL) ? "none" : lower_srtt_prefix->if_name, MAX_CAPACITY_ESTIMATE, (lower_capacity_prefix == NULL) ? "none" : lower_capacity_prefix->if_name);
            // Lower SRTT prefix is safe to use because it does not have the least capacity
            chosenpfx = lower_srtt_prefix;
            // Add MPTCP option to sockopts_suggested, so it will be set on the new socket in case a new connection is established
            _muacc_add_sockopt_to_list(&(rctx->ctx->sockopts_suggested), SOL_TCP, 42, &enabled, sizeof(enabled), 0);
            strbuf_printf(sb, "\tBinding to lower latency prefix and enabling MPTCP\n");
            if (chosenpfx != NULL) {
                _muacc_logtofile(logfile, "%s,mptcp_safe\n", chosenpfx->if_name);
            }
        } else */
        if (lower_capacity_prefix != NULL) {
            strbuf_printf(sb, "\tLow capacity (%s) interface: %s\n", MAX_CAPACITY_ESTIMATE, lower_capacity_prefix->if_name);
            double max_rate = lookup_value(lower_capacity_prefix, MAX_CAPACITY_ESTIMATE, sb);
            strbuf_printf(sb, "\tHave to consider max rate %f and file size %d\n", max_rate, filesize);
            if (duration > 10 && max_rate * 8 > filesize) {
                strbuf_printf(sb, "\tIs enough -- Binding to this prefix and enabling MPTCP\n", max_rate, filesize);
                _muacc_add_sockopt_to_list(&(rctx->ctx->sockopts_suggested), SOL_TCP, 42, &enabled, sizeof(enabled), 0);
                chosenpfx = lower_srtt_prefix;
                if (chosenpfx != NULL) {
                    _muacc_logtofile(logfile, "mptcp,enough\n", chosenpfx->if_name);
                }
                set_to_zero(spl);
            } else if (max_rate * 4 > filesize) {
                strbuf_printf(sb, "\tSeems enough even with low buffer -- Binding to this prefix and enabling MPTCP\n", max_rate, filesize);
                _muacc_add_sockopt_to_list(&(rctx->ctx->sockopts_suggested), SOL_TCP, 42, &enabled, sizeof(enabled), 0);
                chosenpfx = lower_srtt_prefix;
                if (chosenpfx != NULL) {
                    _muacc_logtofile(logfile, "mptcp,enough_low\n", chosenpfx->if_name);
                }
                set_to_zero(spl);
            } else {
                strbuf_printf(sb, "\tIs not enough -- Trying to use higher capacity prefix\n");
                struct src_prefix_list *higher_capacity_prefix = get_highest_capacity_prefix(spl, MAX_CAPACITY_ESTIMATE, sb);
                if (higher_capacity_prefix != NULL && higher_capacity_prefix != lower_capacity_prefix) {
                    strbuf_printf(sb, "\tOnly using higher capacity prefix %s\n", higher_capacity_prefix->if_name);
                    chosenpfx = higher_capacity_prefix;
                     if (chosenpfx != NULL) {
                        _muacc_logtofile(logfile, "%s,onlyhigh\n", chosenpfx->if_name);
                    }
                    increment_non_chosen(spl, chosenpfx, 0);
               }
            }
        }
    }
    if (chosenpfx == NULL) {
        // No category given or someting -- return default prefix
        chosenpfx = get_default_prefix(rctx, sb);
        strbuf_printf(sb, "\tDefault interface: %s\n", (chosenpfx == NULL) ? "none" : chosenpfx->if_name);
        if (chosenpfx != NULL) {
            _muacc_logtofile(logfile, "%s,default\n", chosenpfx->if_name);
        } else {
            _muacc_logtofile(logfile, ",none\n");
        }
    }

    return chosenpfx;
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
	printf("Policy module \"mptcp_selective\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);
    set_to_zero(in4_enabled);
    set_to_zero(in6_enabled);

	logfile = g_hash_table_lookup(mctx->policy_set_dict, "logfile");
	if (logfile != NULL)
	{
		printf("\nLogging to %s\n", logfile);
	}

	printf("\nPolicy module \"mptcp_selective\" has been loaded.\n");
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

	printf("Policy mptcp_selective library cleaned up.\n");
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

    //printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);
    //printf("\n\t[%.6f] Returning resolve result callback\n\n", gettimestamp());
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

	//printf("%s\n", strbuf_export(&sb));
	strbuf_release(&sb);

	//printf("\t[%.6f] Returning resolve_name.\n\n", gettimestamp());
	return 0;
}

/** Resolve request function (mandatory)
 *  Is called upon each getaddrinfo request from a client
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	//printf("\n\t[%.6f] Resolve request: %s:%s\n\n", gettimestamp(), (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		//printf("\tBind interface already specified\n");
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;

		struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
		if (bind_pfx != NULL) {
			// Set DNS base to this prefix's
			rctx->evdns_base = bind_pfx->evdns_base;
			//printf("\tSet DNS base\n");
		}
	}

	rctx->action = muacc_act_getaddrinfo_resolve_resp;

	//printf("\n\t[%.6f] Calling resolve_name\n", gettimestamp());
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

    // Print Intents
    intent_category_t category = -1;
    socklen_t categorylen = sizeof(intent_category_t);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_CATEGORY, &categorylen, &category) == 0) {
        printf("\t\twith category %d\n", category);
    }

	int fs = -1;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) == 0) {
        printf("\t\twith file size %d\n", fs);
    }

	int bitrate = -1;
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_BITRATE, &fslen, &bitrate) == 0) {
        printf("\t\twith bitrate %d\n", bitrate);
    }

	GSList *spl = NULL;
	if (rctx->ctx->domain == AF_INET)
		spl = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		spl = in6_enabled;
	else
		spl = g_slist_concat(in4_enabled, in6_enabled);

	// Check if client has already chosen a source address to bind to
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;
	}
	else
	{
		// search lower srtt prefix, and set it as bind_sa in the request context if found
		struct src_prefix_list *bind_pfx = select_pfx_or_mptcp(rctx, spl, category, bitrate / 8 * SEGMENT_DURATION, 0, &sb);
		if (bind_pfx != NULL) {
			//_muacc_logtofile(logfile, "%s,lowlatency\n", bind_pfx->if_name);
			set_bind_sa(rctx, bind_pfx, &sb);
		}
	}

	// send response back
	strbuf_printf(&sb, "\n\t[%.6f] Sending reply\n", gettimestamp());
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);

    //printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);

	//printf("\t[%.6f] Returning\n\n", gettimestamp());
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

	printf("\n\t[%.6f] Socketconnect request: %s:%s\n\n", gettimestamp(), (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	double timestamp = gettimestamp();
	_muacc_logtofile(logfile, "%.6f,,,,,,,,", timestamp);

    // Print Intents
    intent_category_t category = -1;
    socklen_t categorylen = sizeof(intent_category_t);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_CATEGORY, &categorylen, &category) == 0) {
        printf("\t\twith category %d\n", category);
    }

	int fs = -1;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) == 0) {
        printf("\t\twith file size %d\n", fs);
    }

	int bitrate = -1;
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_BITRATE, &fslen, &bitrate) == 0) {
        printf("\t\twith bitrate %d\n", bitrate);
    }

	int duration = -1;
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_DURATION, &fslen, &duration) == 0) {
        printf("\t\twith duration %d\n", duration);
    }

	_muacc_logtofile(logfile, "%d,%d,%d,%d,", category, fs, bitrate, duration);

    GSList *spl = NULL;
	if (rctx->ctx->domain == AF_INET)
		spl = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		spl = in6_enabled;
	else
		spl = g_slist_concat(in4_enabled, in6_enabled);


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
		struct src_prefix_list *bind_pfx = select_pfx_or_mptcp(rctx, spl, category, bitrate / 8 * SEGMENT_DURATION, duration, &sb);
		if (bind_pfx != NULL) {
			set_bind_sa(rctx, bind_pfx, &sb);
			//_muacc_logtofile(logfile, "%s,lowsrtt\n", bind_pfx->if_name);

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

	printf("\n\t[%.6f] Socketchoose request: %s:%s\n\n", gettimestamp(), (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	double timestamp = gettimestamp();
	_muacc_logtofile(logfile, "%.6f,", timestamp);

    if (rctx->sockets != NULL)
    {
        printf(" with socketset: ");
        print_sockets(rctx->sockets);
    }
    printf("\n");

    // Print Intents
    intent_category_t category = -1;
    socklen_t categorylen = sizeof(intent_category_t);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_CATEGORY, &categorylen, &category) == 0) {
        printf("\t\twith category %d\n", category);
    }

	int fs = -1;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) == 0) {
        printf("\t\twith file size %d\n", fs);
    }

	int bitrate = -1;
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_BITRATE, &fslen, &bitrate) == 0) {
        printf("\t\twith bitrate %d\n", bitrate);
    }

	int duration = -1;
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_DURATION, &fslen, &duration) == 0) {
        printf("\t\twith duration %d\n", duration);
    }

	GSList *spl = in4_enabled;
    GSList *spl2 = spl;
	while (spl != NULL)
	{
        struct src_prefix_list *cur = spl->data;
        struct sample_info *pfxinfo = cur->policy_info;

		pfxinfo->reuse = count_sockets_on_prefix(rctx->sockets, cur, logfile);
		_muacc_logtofile(logfile, "%d,", pfxinfo->reuse);
		spl = spl->next;
	}
	_muacc_logtofile(logfile, ",,,%d,%d,%d,%d,", category, fs, bitrate, duration);
    spl = spl2;

	struct src_prefix_list *bind_pfx = NULL;

	// Check if source address was already chosen
	if(rctx->ctx->bind_sa_req == NULL)
	{
		// No source address chosen yet - choose best prefix
		bind_pfx = select_pfx_or_mptcp(rctx, spl, category, bitrate / 8 * SEGMENT_DURATION, duration, &sb);
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
