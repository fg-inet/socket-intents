/** \file policy_earliest_arrival_countconns.c
 *  \brief Policy that counts connections and tries to infer number of open ones
 *
 *  \copyright Copyright 2013-2017 Philipp Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Behavior:
 *  Getaddrinfo   - Resolve names using the default dns_base from the MAM context
 *  Connect       - Choose the prefix with the shortest predicted completion time
 *  Socketconnect - Choose the prefix with the shortest predicted completion time and resolve name on it
 *  Socketchoose  - Choose a socket on the prefix with the shortest predicted completion time
 *
 *  This EAF Policy first judges whether a new object is latency-dominated or
 *  bandwith-dominated by calculating the "latency part" and the "bandwidth part"
 *  on the interface with the lowest latency.
 *  If it is latency-dominated, it chooses the interface with the lowest latency.
 *  If it is bandwidth-dominated, it compares the predicted completion times
 *  (latency + bandwidth part) of all interfaces and chooses the lowest one.
 *  For calculating the bandwidth part, it divides the max_rate by the number of
 *  connections, of which it keeps track by analyzing the sockets offered for reuse.
 *  It differentiates between "small" connections (that were latency-dominated) and 
 * "big" ones (that were bandwidth-dominated).
 * Caveat: If we our application is talking to a different remote host, it will
 * not offer us a socket for reuse even if it has released the socket.
 * So we will heavily overestimate the actual number of open connections.
 * Furthermore, if these connections are persistent but idle, we will underestimate
 * the available capacity, because we assume all connections are busy when we
 * divide capacity.
 */

#include "policy_earliest_arrival_base.h"

double get_capacity_with_count(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb);

#define EAF_COUNT_NOISY_DEBUG 0

double get_latency_part(struct src_prefix_list *pfx, strbuf_t *sb, int ssl_used);
double get_bandwidth_part (struct src_prefix_list *pfx, int filesize, strbuf_t *sb);
int is_latency_dominated(struct src_prefix_list *pfx, int filesize, request_context_t *rctx, strbuf_t *sb);
void dec_conn_counts(GSList *spl, request_context_t *rctx);

int penalize_by_utilization(struct src_prefix_list *pfx);
int is_utilization_over_threshold(struct src_prefix_list *pfx, double threshold, strbuf_t *sb);
double lookup_utilization_threshold(struct src_prefix_list *pfx);

void choose_this_prefix(struct request_context *rctx, struct src_prefix_list *bind_pfx, strbuf_t *sb)
{
	struct eafirst_info *pfxinfo = bind_pfx->policy_info;
	set_bind_sa(rctx, bind_pfx, sb);

	// If this prefix has sockets to reuse
	if (pfxinfo->reuse)
	{
		// Assume one of the sockets will be reused
		// Decrease counter of available sockets already seen for next time
		pfxinfo->reuse_prev--;

		// Find out which of the actual sockets is gonna be suggested for reuse
		struct socketlist *first_socket = find_socket_on_prefix(rctx->sockets, bind_pfx);
		if (first_socket != NULL && first_socket->file != 0)
		{
			double current_timestamp = gettimestamp();
			// Set timestamp of last modification for this socket
			pfxinfo->sockettimestamps[first_socket->file] = current_timestamp;

			// If socket to be suggested is found, insert it info an array
			// Either into the one counting "big" transfers (bandwidth dominated)
			// or into the one for "small" transfers (latency dominated)
			if (pfxinfo->count > pfxinfo->count_prev)
			{
				DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s: inserting %d (big)]\n", current_timestamp, bind_pfx->if_name, first_socket->file);
				insert_socket(pfxinfo->sockets_big, first_socket->file);
			}
			else
			{
				DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s: inserting %d (small)]\n", current_timestamp, bind_pfx->if_name, first_socket->file);
				insert_socket(pfxinfo->sockets_small, first_socket->file);
			}
		}
	}
}

void dec_conn_counts(GSList *spl, request_context_t *rctx)
{
	while (spl != NULL)
	{
		struct src_prefix_list *cur = spl->data;
		struct eafirst_info *pfxinfo = cur->policy_info;

		if (pfxinfo->reuse)
		{
			int reuse_diff = pfxinfo->reuse - pfxinfo->reuse_prev;
			if (reuse_diff > 0)
			{
				DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s reuse = %d, reuse_prev = %d in dec_conn_counts]\n", gettimestamp(), cur->if_name, pfxinfo->reuse, pfxinfo->reuse_prev);
				int decreased = 0;
				// there are more sockets than last time
				// find out which socket is new (part of one of our socket arrays)
				// decrease counter for that array
				struct socketlist *sockets = rctx->sockets;
				while (sockets != NULL)
				{
					double current_timestamp = gettimestamp();
					double last_timestamp_for_this_socket = pfxinfo->sockettimestamps[sockets->file];
					double *min_srtt = lookup_prefix_info(cur, "srtt_minimum");
					if (last_timestamp_for_this_socket > 0 && min_srtt != NULL && *min_srtt > EPSILON)
					{
						DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s: checking %d: time diff = %.3f, min_srtt = %.3f)]\n", current_timestamp, cur->if_name, sockets->file, (current_timestamp - last_timestamp_for_this_socket) * 1000, *min_srtt);
						if ((current_timestamp - last_timestamp_for_this_socket) < (*min_srtt/1000))
						{
							DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s: too soon to reuse %d or decrease count for it (lt = %.6f)]\n", current_timestamp, cur->if_name, sockets->file, last_timestamp_for_this_socket);
							reuse_diff--;
							pfxinfo->reuse--;
							sockets->flags |= MUACC_SOCKET_IN_USE;
							DLOG(EAF_COUNT_NOISY_DEBUG, "Setting flag: %d\n", sockets->flags);
							sockets = sockets->next;
							continue;
						}
					}

					if (take_socket_from_array(pfxinfo->sockets_small, sockets->file) && pfxinfo->count_small > 0 && decreased < reuse_diff)
					{
						// Socket was found in list of small sockets
						pfxinfo->count_small--;
						DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s dec count_small to %d because %d was found]\n", current_timestamp, cur->if_name, pfxinfo->count_small, sockets->file);
						decreased++;
					}
					else
					{
						if (take_socket_from_array(pfxinfo->sockets_big, sockets->file) && pfxinfo->count > 0 && decreased < reuse_diff)
						{
							// Socket was found in list of big sockets
							pfxinfo->count--;
							DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s dec count to %d because %d was found]\n", current_timestamp, cur->if_name, pfxinfo->count, sockets->file);
							decreased++;
						}
					}

					sockets = sockets->next;
				}
				while (reuse_diff > decreased && (pfxinfo->count_small > 0 || pfxinfo->count > 0))
				{
				// We need to decrease some more
					if (pfxinfo->count_small > 0)
					{
						pfxinfo->count_small--;
						DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s dec count_small to %d]\n", gettimestamp(), cur->if_name, pfxinfo->count_small);
						decreased++;
					}
					else
					{
						if (pfxinfo->count > 0)
						{
							pfxinfo->count--;
							DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s dec count to %d]\n", gettimestamp(), cur->if_name, pfxinfo->count);
							decreased++;
						}
					}
				}
			}
		}
		pfxinfo->reuse_prev = pfxinfo->reuse;

		spl = spl->next;
	}
}

/* Compute free capacity on a prefix */
double get_capacity_with_count(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	// Compute free capacity on the link
	double free_capacity = max_rate;

    struct eafirst_info *pfxinfo = pfx->policy_info;

	DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s: Using count_small = %d and count = %d]\n", gettimestamp(), pfx->if_name, pfxinfo->count_small, pfxinfo->count);
    free_capacity = free_capacity / (pfxinfo->count + pfxinfo->count_small + 1);

	if (free_capacity < EPSILON)
	{
		strbuf_printf(sb, " Got invalid free capacity: %f\n", free_capacity);
		return -1;
	}

	strbuf_printf(sb, "free capacity: %.2f (conns: %d small, %d big)\n", free_capacity, pfxinfo->count_small, pfxinfo->count);

	return free_capacity;
}

double get_latency_part(struct src_prefix_list *pfx, strbuf_t *sb, int ssl_used)
{
	double srtt = lookup_value(pfx, "srtt_minimum_recent", sb);
	struct eafirst_info *pfxinfo = pfx->policy_info;

	double latency_part = 0;
	if (pfxinfo->reuse) {
		latency_part = srtt;
	}
	else
	{
		latency_part = 2 * srtt;
        if (ssl_used) {
            // Assume TLS 1.2 with 2-RTT handshake
            latency_part = latency_part + 2 * srtt;
        }
	}
	return latency_part;
}

double get_bandwidth_part (struct src_prefix_list *pfx, int filesize, strbuf_t *sb)
{
	double max_rate = lookup_value(pfx, "download_rate_max_recent", sb);
	double free_capacity = get_capacity_with_count(pfx, max_rate, lookup_value(pfx, "download_rate_current", NULL), sb);

	double bandwidth_part = 1000 * (filesize / free_capacity);
	return bandwidth_part;
}

int is_latency_dominated(struct src_prefix_list *pfx, int filesize, request_context_t *rctx, strbuf_t *sb)
{
    if (pfx == NULL) {
        return 0;
    }
    int ssl_used = (strncmp(rctx->ctx->remote_service, "443", 4) == 0 ? 1 : 0);
	strbuf_printf(sb, "\tGetting latency and bandwidth part for object (size = %d B) port %s %s\n", filesize, rctx->ctx->remote_service, (ssl_used ? "(TLS)" : ""));
	double latency_part = get_latency_part(pfx, NULL, ssl_used);
	double bandwidth_part = get_bandwidth_part(pfx, filesize, NULL);

	strbuf_printf(sb, "\t\t--> latency part = %.2f, bandwidth part = %.2f", latency_part, bandwidth_part);
	if (latency_part > bandwidth_part)
	{
		strbuf_printf(sb, " (latency dominated) ");
		return 1;
	}
	else
	{
		strbuf_printf(sb, " (bandwidth dominated)\n");
		return 0;
	}
}

int is_utilization_over_threshold(struct src_prefix_list *pfx, double threshold, strbuf_t *sb)
{
	if (pfx == NULL) {
		return 0;
	}
	double channelutilization = lookup_value(pfx, "channel_utilization", sb);
	if (channelutilization > threshold) {
		strbuf_printf(sb, "\tutilization %f > threshold %f!\n", channelutilization, threshold);
		return 1;
	} else {
		return 0;
	}
}

/* Look into the policy dictionary for this prefix, return utilization threshold [%]
   Default is 100%, so interface will never be flagged for exceeding its threshold. */
double lookup_utilization_threshold(struct src_prefix_list *pfx)
{
    double threshold = 100;
    if (pfx->policy_set_dict != NULL) {
        gpointer value = NULL;
        if ((value = g_hash_table_lookup(pfx->policy_set_dict, "utilization_threshold")) != NULL) {
            threshold = (double) atoi(value);
        }
    }
    return threshold;
}

int penalize_by_utilization(struct src_prefix_list *pfx)
{
    if (pfx->policy_set_dict != NULL) {
        gpointer value = NULL;
        if ((value = g_hash_table_lookup(pfx->policy_set_dict, "penalize_by_utilization")) != NULL) {
            return 1;
        }
    }
    return 0;
}

struct src_prefix_list *get_best_prefix(GSList *spl, int filesize, request_context_t *rctx, const char *logfile, strbuf_t *sb)
{
    struct src_prefix_list *chosenpfx = NULL;

	// Decrease counters for finished transfers
	dec_conn_counts(spl, rctx);

	struct src_prefix_list *low_srtt_pfx = get_lowest_srtt_pfx(spl, "srtt_minimum_recent", sb);
	int latency_dominated = 0;

	if (low_srtt_pfx != NULL) {
		struct eafirst_info *pfxinfo = low_srtt_pfx->policy_info;
		// Check if object is latency dominated
		if (is_latency_dominated(low_srtt_pfx, filesize, rctx, sb))
		{
			latency_dominated = 1;
			chosenpfx = low_srtt_pfx;
			double total_time = get_latency_part(chosenpfx, NULL, (strncmp(rctx->ctx->remote_service, "443", 4) == 0 ? 1 : 0)) + get_bandwidth_part(chosenpfx, filesize, NULL);
			strbuf_printf(sb, " -> getting lowest latency interface\n");
			pfxinfo->count_small++;

			DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s inc count_small to %d]\n", gettimestamp(), chosenpfx->if_name, pfxinfo->count_small);
			_muacc_logtofile(logfile, ",,,%.2f,%d,%d,%s_lowrtt\n", total_time, pfxinfo->count, pfxinfo->count_small, chosenpfx->if_name);
		}
	}

	if (latency_dominated)
	{
		return chosenpfx;
	}
	// Save prefix list for later use
	GSList *spl2 = spl;

	// Go through list of possible source prefixes
	while (spl != NULL)
	{
		struct src_prefix_list *cur = spl->data;
        struct eafirst_info *pfxinfo = cur->policy_info;

		double max_rate = lookup_value(cur, "download_rate_max_recent", sb);
		double rate = lookup_value(cur, "download_rate_current", sb);
		double free_capacity = get_capacity(cur, max_rate, rate, sb);

		// Predict completion time on this prefix
		pfxinfo->predicted_time = predict_completion_time(cur, filesize, pfxinfo->reuse, sb, (strncmp(rctx->ctx->remote_service, "443", 4) == 0 ? 1 : 0), free_capacity, "srtt_median_recent");

		spl = spl->next;
	}

	// Get prefix with shortest predicted completion time
	chosenpfx = get_fastest_prefix(spl2);

	// Check if we have a fastest prefix with a reasonable completion time
	if (chosenpfx != NULL && chosenpfx->policy_info != NULL)
	{
		struct eafirst_info *pfxinfo = chosenpfx->policy_info;
		double min_completion_time = pfxinfo->predicted_time;
		if (min_completion_time > EPSILON && min_completion_time < DBL_MAX)
		{
			// Set source prefix to the fastest prefix, if link is not overloaded
			strbuf_printf(sb, "\tFastest prefix is on %s (%.2f ms)\n", chosenpfx->if_name, min_completion_time);
			pfxinfo->count_prev = pfxinfo->count;
            pfxinfo->count++;
            DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s: inc count to %d]\n", gettimestamp(), chosenpfx->if_name, pfxinfo->count);
			_muacc_logtofile(logfile, ",,,%.2f,%d,%d,%s_highbw\n", min_completion_time, pfxinfo->count, pfxinfo->count_small, chosenpfx->if_name);
		}
		else
		{
			strbuf_printf(sb, "\tGot completion time of %.2f ms on %s - not taking it\n", min_completion_time, chosenpfx->if_name);
			chosenpfx = get_default_prefix(spl2, rctx, sb);
			_muacc_logtofile(logfile, ",,,%.2f,%d,%d,%s_default\n", min_completion_time, pfxinfo->count, pfxinfo->count_small, chosenpfx->if_name);
		}
	}
	else
	{
		strbuf_printf(sb, "\tCould not determine fastest prefix\n");
		chosenpfx = get_default_prefix(spl2, rctx, sb);
		_muacc_logtofile(logfile, ",,,0.0,0,0,%s_default\n", chosenpfx->if_name);
	}
    return chosenpfx;
}
