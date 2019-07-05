/** \file policy_util.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "policy_util.h"
#include "mam/mam_util.h"

#include "dlog.h"

#include <time.h>

#ifndef MAM_POLICY_UTIL_NOISY_DEBUG0
#define MAM_POLICY_UTIL_NOISY_DEBUG0 0
#endif

#ifndef MAM_POLICY_UTIL_NOISY_DEBUG1
#define MAM_POLICY_UTIL_NOISY_DEBUG1 1
#endif

#ifndef MAM_POLICY_UTIL_NOISY_DEBUG2
#define MAM_POLICY_UTIL_NOISY_DEBUG2 0
#endif


int mampol_get_socketopt(struct socketopt *list, int level, int optname, socklen_t *optlen, void *optval)
{
	struct socketopt *current = list;
	int ret = -1;

	while (current != NULL)
	{
		if (current->level == level && current->optname == optname)
		{
			if (current->optval != NULL && optval != NULL)
			{
				*optlen = current->optlen;
				memcpy(optval, current->optval, current->optlen);
			}
			ret = 0;
		}
		current = current->next;
	}
	return ret;
}

void print_pfx_addr (gpointer element, gpointer data)
{
	if (!element)
		return;

	struct src_prefix_list *pfx = element;
	char addr_str[INET6_ADDRSTRLEN+1]; /** String for debug / error printing */

	/* Print first address of this prefix */
	if (pfx->family == AF_INET)
	{
		inet_ntop(AF_INET, &( ((struct sockaddr_in *) (pfx->if_addrs->addr))->sin_addr ), addr_str, sizeof(addr_str));
		printf("\n\t\t%s", addr_str);
	}
	else if (pfx->family == AF_INET6)
	{
		inet_ntop(AF_INET6, &( ((struct sockaddr_in6 *) (pfx->if_addrs->addr))->sin6_addr ), addr_str, sizeof(addr_str));
		printf("\n\t\t%s", addr_str);
	}

	/* Print policy info if available */
	if (pfx->policy_info != NULL)
		print_policy_info((void*) pfx->policy_info);
}

void make_v4v6_enabled_lists (GSList *baselist, GSList **v4list, GSList **v6list)
{
	printf("Configured addresses:");
	printf("\n\tAF_INET: ");
	filter_prefix_list (baselist, v4list, PFX_ENABLED, NULL, AF_INET, NULL);
	if (*v4list != NULL)
		g_slist_foreach(*v4list, &print_pfx_addr, NULL);
	else
		printf("\n\t\t(none)");

	printf("\n\tAF_INET6: ");
	filter_prefix_list (baselist, v6list, PFX_ENABLED, NULL, AF_INET6, NULL);
	if (*v6list != NULL)
		g_slist_foreach(*v6list, &print_pfx_addr, NULL);
	else
		printf("\n\t\t(none)");
}

void set_bind_sa(request_context_t *rctx, struct src_prefix_list *chosen, strbuf_t *sb)
{
	if(sb != NULL)
	{
		strbuf_printf(sb, "\n\tSet src=");
		_muacc_print_sockaddr(sb, chosen->if_addrs->addr, chosen->if_addrs->addr_len);
	}
	
	rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(chosen->if_addrs->addr, chosen->if_addrs->addr_len);
	rctx->ctx->bind_sa_suggested_len = chosen->if_addrs->addr_len;
	rctx->ctx->domain = chosen->family;
}

void _set_bind_sa(request_context_t *rctx, struct sockaddr *addr, strbuf_t *sb)
{
	strbuf_printf(sb, "\n\tSet src=");
	_muacc_print_sockaddr(sb, addr, sizeof(struct sockaddr));

	rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(addr, sizeof(struct sockaddr));
	rctx->ctx->bind_sa_suggested_len = sizeof(struct sockaddr);
}


void print_addrinfo_response (struct addrinfo *res)
{
	strbuf_t sb;
	strbuf_init(&sb);

	struct addrinfo *item = res;
	while (item != NULL)
	{
		strbuf_printf(&sb, "\t");
		if (item->ai_family == AF_INET)
			_muacc_print_sockaddr(&sb, item->ai_addr, sizeof(struct sockaddr_in));
		else if (item->ai_family == AF_INET6)
			_muacc_print_sockaddr(&sb, item->ai_addr, sizeof(struct sockaddr_in6));

		strbuf_printf(&sb, "\n");
		item = item->ai_next;
	}

	printf("%s\n", strbuf_export(&sb));
	strbuf_release(&sb);
}

void *lookup_prefix_info(struct src_prefix_list *prefix, const void *key)
{
	if (prefix == NULL || key == NULL)
	{
		DLOG(MAM_POLICY_UTIL_NOISY_DEBUG1, "Warning: Tried to look up info for NULL prefix or NULL key\n");
		return NULL;
	}

	void *value = NULL;
	if (prefix->policy_set_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->policy_set_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in prefix policy_set_dict\n", (char* )key);
			return value;
		}
	}
	if (prefix->measure_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->measure_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in prefix measure_dict\n", (char *) key);
			return value;
		}
	}
	if (prefix->iface != NULL && prefix->iface->policy_set_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->iface->policy_set_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in iface policy_set_dict\n", (char *) key);
			return value;
		}
	}
	if (prefix->iface != NULL && prefix->iface->measure_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->iface->measure_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in iface measure_dict\n", (char *) key);
			return value;
		}
	}
	return value;
}

double lookup_value(struct src_prefix_list *prefix, const void *key, strbuf_t *sb)
{
    if (prefix == NULL)
        return 0;

    void *value = lookup_prefix_info(prefix, key);
    if (value == NULL) {
        strbuf_printf(sb, "\t\t%s: N/A,\t", key);
        return 0;
    }
    // Treating values as double by default
    double returnvalue = *(double *) value;

    if (strncmp(key, "num_conns", 9) == 0) {
        // Have to convert int to double
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Num_conns == %d\n", *(int *) value);
        returnvalue = *(int *) value;
    }

    if (returnvalue < EPSILON )
    {
        strbuf_printf(sb, "\t\t%s: 0,\t", key);
        return 0;
    }
    if ((DBL_MAX - returnvalue) < EPSILON)
    {
        strbuf_printf(sb, "\t\t%s: DBL_MAX -- returning 0,\t", key);
        return 0;
    }
    strbuf_printf(sb, "\t\t%s: %f,\t", key, returnvalue);
    return returnvalue;
}

int is_there_a_socket_on_prefix(struct socketlist *list, struct src_prefix_list *pfx)
{
    if (count_sockets_on_prefix(list, pfx, NULL) > 0)
        return 1;
    else
        return 0;
}

int count_sockets_on_prefix(struct socketlist *list, struct src_prefix_list *pfx, const char *logfile)
{
	strbuf_t sb;
	strbuf_init(&sb);

	int counter = 0;
	struct socketlist *current = list;

	while (current != NULL)
	{
		if (current->ctx == NULL)
		{
			continue;
		}

		// Find sockaddr of this socket
		struct sockaddr *addr = NULL;
		socklen_t addrlen = 0;

		if (current->ctx->bind_sa_suggested != NULL)
		{
			addr = current->ctx->bind_sa_suggested;
			addrlen = current->ctx->bind_sa_suggested_len;
		}
		else if (current->ctx->bind_sa_req != NULL)
		{
			addr = current->ctx->bind_sa_req;
			addrlen = current->ctx->bind_sa_req_len;
		}
		strbuf_printf(&sb, "Socket %d has address ", current->file);
		_muacc_print_sockaddr(&sb, addr, addrlen);

		if (addr != NULL && is_addr_in_prefix(addr, pfx) == 0)
		{
			strbuf_printf(&sb, " - matches prefix!\n");
            counter++;
            if (logfile != NULL)
                _muacc_logtofile(logfile, "%d-", current->file);
		}
		current = current->next;
	}
	strbuf_printf(&sb, "Reached end of function and no address for this prefix found\n");

	DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	if (logfile != NULL)
		_muacc_logtofile(logfile, ",");
	return counter;
}

struct socketlist *find_socket_on_prefix(struct socketlist *sockets, struct src_prefix_list *pfx)
{
	while (sockets != NULL)
	{
		if (sockets->ctx == NULL)
		{
			continue;
		}

		struct sockaddr *addr = NULL;

		if (sockets->ctx->bind_sa_suggested != NULL)
		{
			addr = sockets->ctx->bind_sa_suggested;
		}
		else if (sockets->ctx->bind_sa_req != NULL)
		{
			addr = sockets->ctx->bind_sa_req;
		}

		if (addr != NULL && is_addr_in_prefix(addr, pfx) == 0 && !(sockets->flags & MUACC_SOCKET_IN_USE))
		{
			return sockets;
		}
		sockets = sockets->next;
	}
	return NULL;
}

void pick_sockets_on_prefix(request_context_t *rctx, struct src_prefix_list *bind_pfx)
{
	strbuf_t sb;
	strbuf_init(&sb);

	struct socketlist *current = rctx->sockets;
	struct socketlist *suggested = NULL;
    int mptcp_enabled = 0;
    socklen_t intlen = sizeof(int);
    if (mampol_get_socketopt(rctx->ctx->sockopts_suggested, SOL_TCP, 42, &intlen, &mptcp_enabled) == 0) {
        printf("\n\t\tFound MPTCP option: %d\n", mptcp_enabled);
    }

	while (current != NULL)
	{
		if (current->ctx == NULL)
		{
			continue;
		}

		// Find sockaddr of this socket
		struct sockaddr *addr = NULL;
		socklen_t addrlen = 0;
        int this_socket_has_mptcp = 0;

		if (current->ctx->bind_sa_suggested != NULL)
		{
			addr = current->ctx->bind_sa_suggested;
			addrlen = current->ctx->bind_sa_suggested_len;
		}
		else if (current->ctx->bind_sa_req != NULL)
		{
			addr = current->ctx->bind_sa_req;
			addrlen = current->ctx->bind_sa_req_len;
		}
		strbuf_printf(&sb, "Socket %d has address ", current->file);
		_muacc_print_sockaddr(&sb, addr, addrlen);

        if (mampol_get_socketopt(current->ctx->sockopts_suggested, SOL_TCP, 42, &intlen, &this_socket_has_mptcp) == 0) {
            printf("\n\t\tThis socket has MPTCP? %d\n", this_socket_has_mptcp);
        }

		if (addr != NULL && is_addr_in_prefix(addr, bind_pfx) == 0 && !(current->flags & MUACC_SOCKET_IN_USE) && this_socket_has_mptcp == mptcp_enabled)
		{
			strbuf_printf(&sb, " - same subnet as prefix - suggesting it");
			if (suggested == NULL)
			{
				suggested = current;
				current = current->next;
				suggested->next = NULL;
			}
			else
			{
				// Append socket to list of suggested sockets
				struct socketlist *slist = suggested;
				while (slist->next != NULL)
					slist = slist->next;
				slist->next = current;
				current = current->next;
				slist->next->next = NULL;

			}
		}
		else
		{
			strbuf_printf(&sb, " - different subnet than prefix or likely in use - removing it");

			struct socketlist *slist_to_free = current;
			current = current->next;
			_muacc_free_ctx(slist_to_free->ctx);
			free(slist_to_free);
		}
	}

	rctx->sockets = suggested;

	DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
}

struct src_prefix_list *get_pfx_with_addr(request_context_t *rctx, struct sockaddr *addr)
{
	if (rctx == NULL || rctx->mctx == NULL || rctx->mctx->prefixes == NULL || addr == NULL)
		return NULL;

	GSList *current = rctx->mctx->prefixes;
	while (current != NULL)
	{
		struct src_prefix_list *currentpfx = (struct src_prefix_list *) current->data;
		if (currentpfx == NULL)
			continue;

		if (is_addr_in_prefix(addr, currentpfx) == 0)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found prefix with the given address!\n");
			return currentpfx;
		}
		current = current->next;
	}
	DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Did not find prefix with the given address!\n");
	return NULL;
}

double gettimestamp()
{
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	double measured_sec = current_time.tv_sec;
	double measured_usec = current_time.tv_usec;
	return (measured_sec + (measured_usec / 1000000));
}

void print_sockets(struct socketlist *sockets)
{
    if (sockets != NULL)
    {
        printf("[ %d", sockets->file);
        while (sockets->next != NULL)
        {
            printf(", %d", sockets->next->file);
            sockets = sockets->next;
        }
        printf(" ]");
    }
}

struct src_prefix_list *get_lowest_srtt_pfx(GSList *prefixes, const char *key, strbuf_t *sb)
{
    DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "trying to get lowest srtt from spl of length %d\n", g_slist_length(prefixes));
	struct src_prefix_list *lowest_srtt_pfx = NULL;
	double lowest_srtt = DBL_MAX;

    while (prefixes != NULL)
    {
		struct src_prefix_list *cur = prefixes->data;
		double *cur_srtt = lookup_prefix_info(cur, key);
		if (cur_srtt != NULL && *cur_srtt > EPSILON && *cur_srtt < lowest_srtt)
		{
			lowest_srtt = *cur_srtt;
			lowest_srtt_pfx = cur;
		}
        if (cur_srtt != NULL) {
            DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "looking at %s: %s == %f\n", cur->if_name, key, *cur_srtt);
        }
        strbuf_printf(sb, "\t%s: %f", cur->if_name, (cur_srtt == NULL ? 0 : *cur_srtt));
        prefixes = prefixes->next;
    }
    if (lowest_srtt_pfx != NULL) {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "found lowest %s: %s == %f\n", lowest_srtt_pfx->if_name, key, lowest_srtt);
    } else {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "Did not find a lowest prefix with key %s!\n", key);
    }
	return lowest_srtt_pfx;
}

struct src_prefix_list *get_lowest_capacity_pfx(GSList *prefixes, const char *key, const char *key2, strbuf_t *sb)
{
    DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "trying to get lowest capacity from spl of length %d\n", g_slist_length(prefixes));
	struct src_prefix_list *lowest_capacity_pfx = NULL;
	double lowest_capacity = DBL_MAX;

    while (prefixes != NULL)
    {
		struct src_prefix_list *cur = prefixes->data;
		double *cur_srtt = lookup_prefix_info(cur, key);
        if (cur_srtt != NULL) {
            DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "looking at %s: %s == %f\n", cur->if_name, key, *cur_srtt);
        }
		if (cur_srtt != NULL && *cur_srtt > EPSILON && *cur_srtt < lowest_capacity)
		{
			lowest_capacity = *cur_srtt;
			lowest_capacity_pfx = cur;
		} else if (key2 != NULL) {
            // Look up alternative key if this one is zero
            cur_srtt = lookup_prefix_info(cur, key2);
            if (cur_srtt != NULL) {
                DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "looking at %s: %s == %f\n", cur->if_name, key2, *cur_srtt);
            }

            if (cur_srtt != NULL && *cur_srtt > EPSILON && *cur_srtt < lowest_capacity)
            {
                lowest_capacity = *cur_srtt;
                lowest_capacity_pfx = cur;
            }
        }
        strbuf_printf(sb, "\t%s: %f", cur->if_name, (cur_srtt == NULL ? 0 : *cur_srtt));
        prefixes = prefixes->next;
    }
    if (lowest_capacity_pfx != NULL) {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "found lowest %s: %s == %f\n", lowest_capacity_pfx->if_name, key, lowest_capacity);
    } else {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "Did not find a lowest prefix with key %s!\n", key);
    }
	return lowest_capacity_pfx;
}

struct src_prefix_list *get_highest_capacity_prefix(GSList *prefixes, const char *key, strbuf_t *sb)
{
    DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "trying to get highest capacity prefix from spl of length %d\n", g_slist_length(prefixes));
	struct src_prefix_list *highest_capacity_prefix = NULL;
	double highest_capacity = 0;

    while (prefixes != NULL)
    {
		struct src_prefix_list *cur = prefixes->data;
		double *cur_capacity = lookup_prefix_info(cur, key);
		if (cur_capacity != NULL && *cur_capacity > EPSILON && *cur_capacity > highest_capacity)
		{
			highest_capacity = *cur_capacity;
			highest_capacity_prefix = cur;
		}
        if (cur_capacity != NULL) {
            DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "looking at %s: %s == %f\n", cur->if_name, key, *cur_capacity);
        }
        strbuf_printf(sb, "\t%s: %f", cur->if_name, (cur_capacity == NULL ? 0 : *cur_capacity));
        prefixes = prefixes->next;
    }
    if (highest_capacity_prefix != NULL) {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "found highest %s: %s == %f\n", highest_capacity_prefix->if_name, key, highest_capacity);
    } else {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "Did not find a highest prefix with key %s!\n", key);
    }
	return highest_capacity_prefix;
}

void insert_socket(int socketarray[], int socket)
{
	socketarray[socket] = 1;
}

int take_socket_from_array(int socketarray[], int socket)
{
	if (socketarray[socket] == 1)
	{
		// Socket was found in the array
		socketarray[socket] = 0;
		return 1;
	}
	else
	{
		// Return False - the socket was not found in the array
		return 0;
	}
}

/* Compute free capacity on a prefix */
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	// Compute free capacity on the link
	double free_capacity = max_rate;
    double usage_ratio = 1;

	int num_conns = lookup_value(pfx, "num_conns", sb);

    if (max_rate > EPSILON) {
        // weigh number of connections by current utilization rate
        usage_ratio = rate / max_rate;
		strbuf_printf(sb, " usage ratio: %f - ", usage_ratio);
        free_capacity = free_capacity / ((num_conns * usage_ratio) + 1);
    } else
    {
		strbuf_printf(sb, " Got invalid free capacity: %f\n", free_capacity);
		return -1;
	}

	strbuf_printf(sb, "free capacity: %.2f (existing conns weighted by usage ratio + 1: %d * %f + 1 = %f)\n", free_capacity, num_conns, usage_ratio, (num_conns * usage_ratio)+1);

	return free_capacity;
}

double completion_time_with_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb, int ssl_used)
{
    // Initial RTT for TCP handshake
    double slowstart_time = rtt;

    if (ssl_used) {
        // Two more RTTs for TLS handshake (assume TLS 1.2)
        slowstart_time += 2 * rtt;
    }
    // Calculate max_chunk to fill up only 80% of the bandwidth...
    int max_chunk = (int) ((bandwidth * 0.8) * (rtt / 1000));

    int rounds = 0;
    int slowstart_chunk = INITIAL_CWND;

    if (slowstart_chunk < max_chunk) {
        filesize = filesize - slowstart_chunk;
        rounds++;
        strbuf_printf(sb, "\n\t\t chunks: %d [%d left] ", slowstart_chunk, filesize);
        while (filesize > 0 && slowstart_chunk < (max_chunk/2))
        {
            rounds++;
            slowstart_chunk += slowstart_chunk;
            filesize = filesize - slowstart_chunk;
            strbuf_printf(sb, " .. %d [%d left] ", slowstart_chunk, filesize);
        }
        if (filesize < 0)
        {
            //filesize = filesize + slowstart_chunk;
            filesize = 0;
            // Entire object fetched in slow start - nothing left to fetch
        }
    } else {
        strbuf_printf(sb, "\n\t\t no slowstart ", slowstart_chunk);
    }

    // Calculating "finally used download rate" based on the last slowstart chunk,
    // divided by the RTT - because that's a conservative estimate for
    // how much we actually transfer in congestion avoidance
    // ... unless our "bandwidth" (free capacity) was tiny anyway,
    // in which case we take this one as the actually used download rate
    double finally_used_download_rate = slowstart_chunk / (rtt / 1000);
    if (finally_used_download_rate > bandwidth)
        finally_used_download_rate = bandwidth;

    // Adding initial RTT to set up connection, RTTs for rounds with slow start, and one final RTT
    slowstart_time += (rounds) * rtt + 1000 * (filesize / finally_used_download_rate);
	strbuf_printf(sb, "\tPredicted %d slow start rounds for new object (chunk threshold = %d, rest of bytes to fetch = %d, finally_used_download_rate = %f)\n", rounds, max_chunk, filesize, finally_used_download_rate);
    return slowstart_time;
}

double completion_time_without_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb)
{
    double time = rtt + 1000 * (filesize / bandwidth);
    return time;
}



/* Estimate completion time of an object of a given file size on this prefix */
double predict_completion_time(struct src_prefix_list *pfx, int filesize, int reuse, strbuf_t *sb, int ssl_used, double free_capacity, const char *srtt_estimate)
{
	if (pfx == NULL)
		return 0;

	strbuf_printf(sb, "\tPredicting completion time for new object (%d bytes) on %s %s, %s\n", filesize, pfx->if_name, reuse ? "(connection reuse)" : "", (ssl_used ? "(TLS)" : ""));

	double completion_time = DBL_MAX;

	double rtt = lookup_value(pfx, srtt_estimate, sb);

	if (free_capacity > EPSILON && rtt > EPSILON)
	{
		if (reuse)
		{
			completion_time = completion_time_without_slowstart(filesize, free_capacity, rtt, sb);
		}
		else
		{
			completion_time = completion_time_with_slowstart(filesize, free_capacity, rtt, sb, ssl_used);

		}

		strbuf_printf(sb, "\t\tEstimated completion time is %.2f ms\n", completion_time);
	}
	else
	{
		// Not all metrics found - cannot compute completion time
		strbuf_printf(sb, "\t\tCannot compute completion time!\n");
	}

	return completion_time;
}
