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

/* For the following functions, see policy_util.c:
   - get_capacity()
   - predict_completion_time()
   - completion_time_with_slowstart()
   - completion_time_without_slowstart()
  */


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

/* For Threshold Policy with Penalty -- not used currently */
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
/* For Threshold Policy with Penalty -- not used currently */
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

/* For Threshold Policy with Penalty -- not used currently */
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

	struct src_prefix_list *low_srtt_pfx = get_lowest_srtt_pfx(spl, "srtt_minimum_recent", sb);
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
