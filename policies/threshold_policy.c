/** \file threshold_policy
 *  \brief Policy that distributes resource loads according to latency and available capacity
 *
 *  \copyright Copyright 2013-2019 Philipp Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Behavior:
 *
 *  This Informed Access Network Selection policy first judges whether a new
 *  resource load is latency-dominated or capacity-dominated. If it is
 *  latency-dominated, it chooses the interface (i.e., the network) with the 
 *  lowest latency. If it is capacity-dominated, it compares the predicted
 *  completion times (latency + capacity part) of all interfaces and chooses the
 *  lowest completion time.
 *
 *  Input variables:
 *
 *  minRTT: Minimum Smoothed RTT of all current connections over a network
 *          (here, on a prefix which is configured on a specific interface)
 *  connectionReusePossible: Whether there is a socket available for reuse over this network
 *  useTLs: Whether the resource is loaded over TLS or plain TCP
 *  maxDRate: Maximum data rate observed in the last 5 minutes on an interface
 *  curDRate: Current data rate observed (i.e., within the last 100 ms) on an interface
 *  numConns: Number of concurrent TCP connections
 *  rSize:    Resource size (i.e., Size to be Received Socket Intent)
 *
 *  Output of the policy: Network to use for loading this resource
 *  with connection reuse: socket of existing TCP connection over this network
 *  without connection reuse: local address to bind a new socket to, whereby the
 *  address is configured on an interface which connects to the chosen network
 *
 *  High-level pseudocode of the policy:
 *
 * 1. Decision algorithm
 *
 *  For network with lowest minRTT :
 *      latencyPart = getLatencyPart(minRTT, connectionReusePossible, useTLS)
 *      capacityPart = getCapacityPart(maxDRate, curDRate, numConns, rSize)

 *  if latencyPart > capacityPart then
 *      Choose network with lowest minRTT
 *  else
 *      for all networks do
 *          loadTime = predictLoadTime(medianRTT, connectionReusePossible,
 *                          useTLS, maxDRate, curDRate, numConns, rSize)
 *      end for
 *      Choose network with lowest loadTime
 *  end if
 *
 *
 *  2. Getting latency and capacity part, estimating capacity
 *
 *  function getLatencyPart(RTT, connectionReusePossible, useTLS)
 *      if connectionReusePossible then
 *          latencyPart = minRTT
 *      else if useTLS then
 *          latencyPart = 4 ∗ minRTT
 *      else
 *          latencyPart = 2 ∗ minRTT
 *      end if
 *      return latencyPart
 *  end function
 *
 *  function getCapacityPart(maxDRate, curDRate, numConns, rSize)
 *      freeCapacity = getFreeCapacity(maxDRate, curDRate, numConns)
 *      capacityPart = rSize/freeCapacity
 *      return capacityPart
 *  end function
 *
 *  function getFreeCapacity(maxDRate, curDRate, numConns)
 *      usageRate = curDRate/maxDRate
 *      freeCapacity = maxDRate/((numConns ∗ usageRate) + 1)
 *      return freeCapacity
 *  end function
 *
 *
 *  3. Resource load time estimation
 *
 *  function predictLoadTime(medianRTT, connectionReusePossible, useTLS,
 *                                  maxDRate, curDRate, numConns, rSize)
 *      freeCapacity = getFreeCapacity(maxDRate, curDRate, numConns)
 *      if connectionReusePossible then
 *          loadTime = medianRTT + (rSize/freeCapacity)
 *      else
 *          # Estimate connection setup time and slow start
 *          if useTLS then
 *              setupTime = 3 ∗ medianRTT
 *          else
 *              setupTime = 1 ∗ medianRTT
 *          end if
 *          slowstartRounds = 0
 *          chunkSize = INITCWND
 *          maxChunk = (freeCapacity ∗ 0.8) ∗ (medianRTT)
 *          while chunk < maxChunk do 
 *              # Emulate one slow-start round, where a chunk of the resource is fetched
 *              slowstartRounds = slowstartRounds + 1
 *              chunkSize = chunkSize ∗ 2
 *              rSize = rSize - chunkSize
 *          end while
 *          usedDownloadRate = chunk/medianRTT
 *          loadTime = setupTime + slowstartRounds ∗ medianRTT + (rSize/usedDownloadRate)
 *      end if
 *      return loadTime
 *  end function
 *
 */

#include "policy_earliest_arrival_base.h"

#define INITIAL_CWND 14480

double completion_time_with_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb, int ssl_used);
double completion_time_without_slowstart(int filesize, double bandwidth, double rtt, strbuf_t *sb);

double get_latency_part(struct src_prefix_list *pfx, strbuf_t *sb, int ssl_used);
double get_bandwidth_part (struct src_prefix_list *pfx, int filesize, strbuf_t *sb);
int is_latency_dominated(struct src_prefix_list *pfx, int filesize, request_context_t *rctx, strbuf_t *sb);

int penalize_by_utilization(struct src_prefix_list *pfx);
int is_utilization_over_threshold(struct src_prefix_list *pfx, double threshold, strbuf_t *sb);
double lookup_utilization_threshold(struct src_prefix_list *pfx);

void choose_this_prefix(struct request_context *rctx, struct src_prefix_list *bind_pfx, strbuf_t *sb)
{
	set_bind_sa(rctx, bind_pfx, sb);
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
double predict_completion_time(struct src_prefix_list *pfx, int filesize, int reuse, strbuf_t *sb, int ssl_used)
{
	if (pfx == NULL)
		return 0;

	struct eafirst_info *pfxinfo = pfx->policy_info;
	strbuf_printf(sb, "\tPredicting completion time for new object (%d bytes) on %s %s, %s\n", filesize, pfx->if_name, (pfxinfo->reuse) ? "(connection reuse)" : "", (ssl_used ? "(TLS)" : ""));

	double completion_time = DBL_MAX;

	double max_rate = lookup_value(pfx, "download_rate_max_recent", sb);
	double rate = lookup_value(pfx, "download_rate_current", sb);
	double free_capacity = get_capacity(pfx, max_rate, rate, sb);
	double rtt = lookup_value(pfx, "srtt_median_recent", sb);

	if (free_capacity > EPSILON && rtt > EPSILON)
	{
		if (pfxinfo->reuse)
		{
			completion_time = completion_time_without_slowstart(filesize, free_capacity, rtt, sb);
		}
		else
		{
			completion_time = completion_time_with_slowstart(filesize, free_capacity, rtt, sb, ssl_used);

		}

		/*if (is_utilization_over_threshold(pfx, lookup_utilization_threshold(pfx), sb)) {
			completion_time = 2 * completion_time;
		}*/
	if (penalize_by_utilization(pfx)) {
		double channelutilization = lookup_value(pfx, "channel_utilization", sb);
		completion_time = completion_time * (1 + channelutilization / 100);
		strbuf_printf(sb, " - increasing estimate -");
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
	double free_capacity = get_capacity(pfx, max_rate, lookup_value(pfx, "download_rate_current", NULL), sb);

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

	struct src_prefix_list *low_srtt_pfx = get_lowest_srtt_pfx(spl, "srtt_minimum_recent");
	int latency_dominated = 0;

	if (low_srtt_pfx != NULL) {
		// Check if object is latency dominated
		if (is_latency_dominated(low_srtt_pfx, filesize, rctx, sb))
		{
			latency_dominated = 1;
			chosenpfx = low_srtt_pfx;
			double total_time = get_latency_part(chosenpfx, NULL, (strncmp(rctx->ctx->remote_service, "443", 4) == 0 ? 1 : 0)) + get_bandwidth_part(chosenpfx, filesize, NULL);
			strbuf_printf(sb, " -> getting lowest latency interface\n");

			_muacc_logtofile(logfile, ",,,%.2f,,,%s_lowrtt\n", total_time, chosenpfx->if_name);
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
		pfxinfo->predicted_time = predict_completion_time(cur, filesize, pfxinfo->reuse, sb, (strncmp(rctx->ctx->remote_service, "443", 4) == 0 ? 1 : 0));

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
			_muacc_logtofile(logfile, ",,,%.2f,,,%s_highbw\n", min_completion_time, chosenpfx->if_name);
		}
		else
		{
			strbuf_printf(sb, "\tGot completion time of %.2f ms on %s - not taking it\n", min_completion_time, chosenpfx->if_name);
			chosenpfx = get_default_prefix(spl2, rctx, sb);
			_muacc_logtofile(logfile, ",,,%.2f,,,%s_default\n", min_completion_time, chosenpfx->if_name);
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
