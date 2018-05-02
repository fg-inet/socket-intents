/** \file policy_earliest_arrival_probabilities.c
 *  \brief Policy that schedules objects based on probabilities based on predicted times
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
 *  (latency + bandwidth part) of all interfaces. 
 *  For calculating the bandwidth part, it divides the max_rate by the number of
 *  connections, of which it keeps track by analyzing the sockets offered for reuse
 *  in a similar fashion as eaf_countconns. Additionally, it differentiates
 *  between "small" connections (that were latency-dominated) and "big" ones
 *  (that were bandwidth-dominated).
 *  It and calculates probabilities based on these timings and then chooses randomly.
 *  Furthermore, it penalizes each choice by the variation of the SRTTs
 *  observed in connections on that interface.
*/

#include "policy_earliest_arrival_base.h"

#define INITIAL_CWND 14880

#define EAF_COUNT_NOISY_DEBUG 0

double completion_time_with_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb);
double completion_time_without_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb);

double get_latency_part(struct src_prefix_list *pfx, strbuf_t *sb);
double get_bandwidth_part (struct src_prefix_list *pfx, int filesize, strbuf_t *sb);
int is_latency_dominated(struct src_prefix_list *pfx, int filesize, request_context_t *rctx, strbuf_t *sb);
void dec_conn_counts(GSList *spl, request_context_t *rctx);
struct src_prefix_list *get_prefix_with_probabilities(GSList *spl, strbuf_t *sb, const char *logfile);
void penalize_interfaces(double *probs, struct src_prefix_list **prefixes, int length, char *penalize_key, char *normalize_key, strbuf_t *sb);

#define MAX_NUMBER_INTERFACES 255

/** Modify interface selection probabilities based of some more properties
 *  such as SRTT variance, which indicates congestion
 */
void penalize_interfaces(double *probs, struct src_prefix_list **prefixes, int length, char *penalize_key, char *normalize_key, strbuf_t *sb)
{
    double penalizevalues[MAX_NUMBER_INTERFACES];
    double multipliers[MAX_NUMBER_INTERFACES];

    strbuf_printf(sb, "\tpenalizevalue %s: ", penalize_key);
    if (normalize_key != NULL) {
        strbuf_printf(sb, "normalized by %s: ", normalize_key);
    }
    for (int i = 0; i < length; i++) {
        double *value = lookup_prefix_info(prefixes[i], penalize_key);

        double normalizevalue = 1;
        if (normalize_key != NULL) {
            double *lookup = lookup_prefix_info(prefixes[i], normalize_key);
            if (lookup != NULL) {
                normalizevalue = *lookup;
            }
        }
        if (value != NULL && *value > 0) {
            penalizevalues[i] = *value / normalizevalue;
            strbuf_printf(sb, "%s: %.3f / %.3f = %.3f ", prefixes[i]->if_name, *value, normalizevalue, penalizevalues[i]);
        } else {
            penalizevalues[i] = 1 / normalizevalue;
            strbuf_printf(sb, "%s: not found, using %.3f ", prefixes[i]->if_name, penalizevalues[i]);
        }
    }
    double divisor = probs[0];
    for (int i = 1; i < length; i++) {
        divisor = divisor + (penalizevalues[0] / penalizevalues[i]) * probs[i];
    }

    multipliers[0] = 1 / divisor;
    for (int i = 1; i < length; i++) {
        multipliers[i] = (penalizevalues[0] / penalizevalues[i]) * multipliers[0];
    }

    strbuf_printf(sb, "\tpenalized probs:");
    for (int i = 0; i < length; i++) {
        probs[i] = probs[i] * multipliers[i];
        strbuf_printf(sb, " %.3f,", probs[i]);
    }
}

/** Choose one of the source prefixes with a probability according to its prediction
 *  The shorter the predicted time, the higher the probability to be chosen.
 *  Only consider interfaces with valid predictions (not 0 or DBL_MAX).
 *  The sum of probabilities is of course 1.
 */
struct src_prefix_list *get_prefix_with_probabilities(GSList *spl, strbuf_t *sb, const char *logfile)
{
    //GList *values = NULL;
    double timings[MAX_NUMBER_INTERFACES];
    double probabilities[MAX_NUMBER_INTERFACES];
    struct src_prefix_list *options[MAX_NUMBER_INTERFACES];

    struct src_prefix_list *cur = NULL;
    int i = 0;
    int valid_predictions = 0;

    while (spl != NULL && i < MAX_NUMBER_INTERFACES)
    {
        cur = spl->data;

        //double *prediction = malloc(sizeof(double));
        double prediction = ((struct eafirst_info *)cur->policy_info)->predicted_time;
        if (prediction > 0 && prediction < DBL_MAX)
        {
            timings[i] = prediction;
            options[i] = cur;

            i++;
            valid_predictions++;
        }
        spl = spl->next;
    }
    if (valid_predictions == 0)
        return NULL;
    if (valid_predictions == 1)
        return options[0];

    double divisor = 1;
    for (i = 1; i < valid_predictions; i++) {
        divisor = divisor + timings[0] / timings[i];
    }
    probabilities[0] = 1 / divisor;
    strbuf_printf(sb, "\tProbabilities: %.3f", probabilities[0]);

    for (i = 1; i < valid_predictions; i++) {
        probabilities[i] = probabilities[0] * (timings[0] / timings[i]);
        strbuf_printf(sb, ", %.3f", probabilities[i]);
    }
 
    char * penalizekey = "srtt_var_mean_within";
    char * normalizekey = NULL;

    if (options[0]->policy_set_dict != NULL) {
        gpointer value = NULL;
        if ((value = g_hash_table_lookup(options[0]->policy_set_dict, "penalize_key")) != NULL)
        {
            penalizekey = (char *) value;
        }
        if ((value = g_hash_table_lookup(options[0]->policy_set_dict, "normalize_key")) != NULL)
        {
            normalizekey = (char *) value;
        }
    }
    penalize_interfaces(probabilities, options, valid_predictions, penalizekey, normalizekey, sb);

    // Generate random number between 0 and 1
    double random_number = (double)rand() / (double)RAND_MAX;
    strbuf_printf(sb, "\n\t\trandom number: %.3f", random_number);

	_muacc_logtofile(logfile, "%f,%f,%f,", probabilities[0], probabilities[1], random_number);

    // Sum up probabilities until they are > random_number.
    // As soon as they are, choose that option.
    double probs_sum = 0;
    for (i = 0; i < valid_predictions; i++) {
        probs_sum = probs_sum + probabilities[i];
        if (probs_sum > random_number) {
            strbuf_printf(sb, " - Choose option %d: %s\n", i, options[i]->if_name);
            return(options[i]);
        }
    }
    // Reached end of list - return last valid option
    return(options[valid_predictions-1]);
}

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
					double *min_srtt = lookup_prefix_info(cur, "srtt_minimum_recent");
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
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb)
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

double completion_time_with_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb)
{
    int max_chunk = (int) (bandwidth * (rtt / 1000));

    int rounds = 1;
    int slowstart_chunk = INITIAL_CWND;
    filesize = filesize - slowstart_chunk;

    while (filesize > 0 && slowstart_chunk < max_chunk)
    {
        rounds++;
        slowstart_chunk += slowstart_chunk;
        filesize = filesize - slowstart_chunk;
    }
    if (filesize < 0)
    {
        filesize = filesize + slowstart_chunk;
    }
    // Adding initial RTT to set up connection, RTTs for rounds with slow start, and one final RTT
    double slowstart_time = (rounds + 1) * rtt + 1000 * (filesize / bandwidth);
	strbuf_printf(sb, "\tPredicted %d slow start rounds for new object (final chunk size = %d, rest of bytes to fetch = %d, BDP = %d)\n", rounds, slowstart_chunk, filesize, max_chunk);
    return slowstart_time;
}

double completion_time_without_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb)
{
    double time = rtt + 1000 * (filesize / bandwidth);
    return time;
}



/* Estimate completion time of an object of a given file size on this prefix */
double predict_completion_time(struct src_prefix_list *pfx, int filesize, int reuse, strbuf_t *sb)
{
	if (pfx == NULL)
		return 0;

	struct eafirst_info *pfxinfo = pfx->policy_info;
	strbuf_printf(sb, "\tPredicting completion time for new object (%d bytes) on %s %s\n", filesize, pfx->if_name, (pfxinfo->reuse) ? "(connection reuse)" : "");

	double completion_time = DBL_MAX;

	double max_rate = lookup_value(pfx, "download_rate_max_recent", sb);
	double rate = lookup_value(pfx, "download_rate_current", sb);
	double free_capacity = get_capacity(pfx, max_rate, rate, sb);
	double rtt = lookup_value(pfx, "srtt_median_recent", sb);

	if (free_capacity > EPSILON && rtt > EPSILON && rtt < DBL_MAX)
	{
		if (pfxinfo->reuse)
		{
			completion_time = completion_time_without_slowstart(filesize, free_capacity, rtt, sb);
		}
		else
		{
			completion_time = completion_time_with_slowstart(filesize, free_capacity, rtt, sb);

		}

		strbuf_printf(sb, "\t\tEstimated completion time is %.2f ms\n", completion_time);
	}
	else
	{
		// Not all metrics found - cannot compute completion time
		strbuf_printf(sb, "\t\tCannot compute completion time!\n");
		_muacc_logtofile(logfile, "0.0,", completion_time);
	}

	return completion_time;
}

double get_latency_part(struct src_prefix_list *pfx, strbuf_t *sb)
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
	}
	return latency_part;
}

double get_bandwidth_part (struct src_prefix_list *pfx, int filesize, strbuf_t *sb)
{
	double max_rate = lookup_value(pfx, "download_rate_max_recent", sb);
	double free_capacity = get_capacity(pfx, max_rate, lookup_value(pfx, "download_rate_current", NULL), sb);

	double bandwidth_part = 1000 * (filesize / free_capacity);
	return bandwidth_part;
}

int is_latency_dominated(struct src_prefix_list *pfx, int filesize, request_context_t *rctx, strbuf_t *sb)
{
    if (pfx == NULL) {
        return 0;
    }
	strbuf_printf(sb, "\tGetting latency and bandwidth part for object (size = %d B)\n", filesize);
	double latency_part = get_latency_part(pfx, NULL);
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

struct src_prefix_list *get_best_prefix(GSList *spl, int filesize, request_context_t *rctx, const char *logfile, strbuf_t *sb)
{
    struct src_prefix_list *chosenpfx = NULL;

	// Decrease counters for finished transfers
	dec_conn_counts(spl, rctx);

	struct src_prefix_list *low_srtt_pfx = get_lowest_srtt_pfx(spl, "srtt_minimum_recent");
	int latency_dominated = 0;

	if (low_srtt_pfx != NULL) {
		struct eafirst_info *pfxinfo = low_srtt_pfx->policy_info;
		// Check if object is latency dominated
		if (is_latency_dominated(low_srtt_pfx, filesize, rctx, sb))
		{
			latency_dominated = 1;
			chosenpfx = low_srtt_pfx;
			double total_time = get_latency_part(chosenpfx, NULL) + get_bandwidth_part(chosenpfx, filesize, NULL);
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

		// Predict completion time on this prefix
		pfxinfo->predicted_time = predict_completion_time(cur, filesize, pfxinfo->reuse, sb);

		spl = spl->next;
	}

	// Get prefix with shortest predicted completion time
	//chosenpfx = get_fastest_prefix(spl2);
    chosenpfx = get_prefix_with_probabilities(spl2, sb, logfile);

	// Check if we have a fastest prefix with a reasonable completion time
	if (chosenpfx != NULL && chosenpfx->policy_info != NULL)
	{
		struct eafirst_info *pfxinfo = chosenpfx->policy_info;
		double min_completion_time = pfxinfo->predicted_time;
		if (min_completion_time > EPSILON && min_completion_time < DBL_MAX)
		{
			// Set source prefix to the fastest prefix, if link is not overloaded
			strbuf_printf(sb, "\tChosen prefix is on %s (%.2f ms)\n", chosenpfx->if_name, min_completion_time);
			pfxinfo->count_prev = pfxinfo->count;
            pfxinfo->count++;
            DLOG(EAF_COUNT_NOISY_DEBUG, "[%.6f][%s: inc count to %d]\n", gettimestamp(), chosenpfx->if_name, pfxinfo->count);
			_muacc_logtofile(logfile, "%.2f,%d,%d,%s_probs\n", min_completion_time, pfxinfo->count, pfxinfo->count_small, chosenpfx->if_name);
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
