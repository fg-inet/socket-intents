/** \file policy_earliest_arrival.c
 *  \brief Policy that calculates the predicted completion time for an object on all prefixes and selects the fastest
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
 *  This EAF Policy counts the connections per interface and keeps track of them
 *  by analyzing the sockets that are offered for reuse.
 *  When predicting the completion time, it divides the max_rate by the number of
 *  connections + 1 to get an estimate of the available capacity.
 */

#include "policy_earliest_arrival_base.h"

void dec_conn_counts(GSList *spl, request_context_t *rctx);

void choose_this_prefix(struct request_context *rctx, struct src_prefix_list *bind_pfx, strbuf_t *sb)
{
	struct eafirst_info *pfxinfo = bind_pfx->policy_info;
	pfxinfo->count++;
	printf("[inc counter on %s to %d]\n", bind_pfx->if_name, pfxinfo->count);
	// if this prefix has sockets to reuse
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

			printf("[%.6f][%s: inserting %d]\n", current_timestamp, bind_pfx->if_name, first_socket->file);
			insert_socket(pfxinfo->sockets_big, first_socket->file);
		}
	}
	set_bind_sa(rctx, bind_pfx, sb);
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
				printf("[%.6f][%s reuse = %d, reuse_prev = %d in dec_conn_counts]\n", gettimestamp(), cur->if_name, pfxinfo->reuse, pfxinfo->reuse_prev);
				int decreased = 0;
				// there are more sockets than last time
				// find out which socket is new (part of one of our socket arrays)
				// decrease counter for that array
				struct socketlist *sockets = rctx->sockets;
				while (sockets != NULL)
				{
					double current_timestamp = gettimestamp();
					double last_timestamp_for_this_socket = pfxinfo->sockettimestamps[sockets->file];
					double *min_srtt = lookup_prefix_info(cur, "srtt_minimum_recent");
					if (last_timestamp_for_this_socket > 0 && min_srtt != NULL && *min_srtt > EPSILON)
					{
						if ((current_timestamp - last_timestamp_for_this_socket) < (*min_srtt/1000))
						{
							// Do not decrement the connection counter for this one
							printf("[%.6f][%s: too soon to reuse %d or decrease count for it (diff = %.3f, min_srtt = %.3f)]\n", current_timestamp, cur->if_name, sockets->file, (current_timestamp - last_timestamp_for_this_socket) * 1000, *min_srtt);
							reuse_diff--;
							pfxinfo->reuse--;

							// mark socket as "in use" so it will not get offered
							sockets->flags |= MUACC_SOCKET_IN_USE;
							printf("Setting flag: %d\n", sockets->flags);

							sockets = sockets->next;
							continue;
						}
					}
					// Try to take the socket from the list of currently used ones
					if (take_socket_from_array(pfxinfo->sockets_big, sockets->file) && pfxinfo->count > 0 && decreased < reuse_diff)
					{
						// Socket was found in list
						pfxinfo->count--;
						printf("[%.6f][%s dec count to %d because %d was found]\n", gettimestamp(), cur->if_name, pfxinfo->count, sockets->file);
						decreased++;
					}

					sockets = sockets->next;
				}
				while (reuse_diff > decreased && pfxinfo->count > 0)
				{
					// We need to decrease some more
					pfxinfo->count--;
					printf("[%.6f][%s dec count to %d]\n", gettimestamp(), cur->if_name, pfxinfo->count);
					decreased++;
				}
			}
		}
		pfxinfo->reuse_prev = pfxinfo->reuse;

		spl = spl->next;
	}
}

/* Look up a smoothed RTT value on a prefix */
double get_srtt(struct src_prefix_list *pfx, strbuf_t *sb)
{
	if (pfx == NULL)
		return 0;

	double *min_srtt = lookup_prefix_info(pfx, "srtt_minimum");

	if (min_srtt == NULL || *min_srtt < EPSILON)
	{
		// If not found or zero: Return
		strbuf_printf(sb, "\t\tMinimum RTT:   N/A,   ");
		return 0;
	}

	strbuf_printf(sb, "\t\tMinimum RTT: %.2f ms, ", *min_srtt);
	return *min_srtt;
}

/* Look up a value for maximum download rate on a prefix */
double get_max_rate(struct src_prefix_list *pfx, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	double *download_max_rate = lookup_prefix_info(pfx, "download_rate_max_recent");

	if (download_max_rate == NULL)
	{
		// If still not found or zero: Return
		strbuf_printf(sb, "download max rate:   N/A,   ");
		return -1;
	}

	strbuf_printf(sb, "download max rate: %.2f, ", *download_max_rate);

	return *download_max_rate;
}

/* Look up a value for current download rate on a prefix */
double get_rate(struct src_prefix_list *pfx, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	double *download_rate = lookup_prefix_info(pfx, "download_rate_current");

	if (download_rate == NULL)
	{
		// If still not found: Return
		strbuf_printf(sb, "download rate:   N/A,   ");
		return -1;
	}

	strbuf_printf(sb, "download rate: %.2f, ", *download_rate);

	return *download_rate;
}

/* Compute free capacity on a prefix */
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	// Compute free capacity on the link
    double free_capacity = max_rate;

    struct eafirst_info *pfxinfo = pfx->policy_info;

    free_capacity = free_capacity / (double) (pfxinfo->count + 1);
    printf("[%s: using count = %d]\n", pfx->if_name, pfxinfo->count);

	if (free_capacity < EPSILON)
	{
		strbuf_printf(sb, " Got invalid free capacity: %f\n", free_capacity);
		return -1;
	}

	strbuf_printf(sb, "free capacity: %.2f (%d conns)\n", free_capacity, pfxinfo->count);

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

	if (srtt > EPSILON && free_capacity > EPSILON)
	{
		if (reuse)
		{
			// Predict completion time for reusing a connection
			completion_time = srtt + 1000 * (filesize / free_capacity);
		}
		else
		{
			// Predict completion time for new connection
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

struct src_prefix_list *get_best_prefix(GSList *spl, int filesize, request_context_t *rctx, const char *logfile, strbuf_t *sb)
{
	struct src_prefix_list *chosenpfx = NULL;
	struct src_prefix_list *cur = NULL;

	// Decrease counters for finished transfers
	dec_conn_counts(spl, rctx);

	// Save prefix list for later use
	GSList *spl2 = spl;

	// Go through list of possible source prefixes
	while (spl != NULL)
	{
		cur = spl->data;
		struct eafirst_info *pfxinfo = cur->policy_info;

		// Predict completion time on this prefix
		pfxinfo->predicted_time = predict_completion_time(cur, filesize, pfxinfo->reuse, sb);

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
			// Set source prefix to the fastest prefix, if link is not overloaded
			strbuf_printf(sb, "\tFastest prefix is on %s (%.2f ms)\n", chosenpfx->if_name, min_completion_time);
			_muacc_logtofile(logfile, "%.2f,%d,,%s_fastest\n", min_completion_time, ((struct eafirst_info *)chosenpfx->policy_info)->count, chosenpfx->if_name);
		}
		else
		{
			strbuf_printf(sb, "\tGot completion time of %.2f ms on %s - not taking it\n", min_completion_time, chosenpfx->if_name);
			chosenpfx = get_default_prefix(spl2, rctx, sb);
			_muacc_logtofile(logfile, "%.2f,%d,,%s_default\n", min_completion_time, ((struct eafirst_info *)chosenpfx->policy_info)->count, chosenpfx->if_name);
		}
	}
	else
	{
		strbuf_printf(sb, "\tCould not determine fastest prefix\n");
		chosenpfx = get_default_prefix(spl2, rctx, sb);
		_muacc_logtofile(logfile, "0.0,,,%s_default\n", chosenpfx->if_name);
	}
	return chosenpfx;
}
