/** \file policy_earliest_arrival.c
 *  \brief Policy that calculates the predicted completion time for an object on all prefixes and selects the fastest
 *
 *  \copyright Copyright 2013-2016 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Behavior:
 *  Getaddrinfo   - Resolve names using the default dns_base from the MAM context
 *  Connect       - Choose the prefix with the shortest predicted completion time
 *  Socketconnect - Choose the prefix with the shortest predicted completion time and resolve name on it
 *  Socketchoose  - Choose a socket on the prefix with the shortest predicted completion time
 */

#include "policy_earliest_arrival_base.h"

#define INITIAL_CWND 14480


void choose_this_prefix(struct request_context *rctx, struct src_prefix_list *bind_pfx, strbuf_t *sb)
{
    set_bind_sa(rctx, bind_pfx, sb);
}

/* Look up a smoothed RTT value on a prefix */
double get_srtt(struct src_prefix_list *pfx, strbuf_t *sb)
{
	if (pfx == NULL)
		return 0;

	double *min_srtt = lookup_prefix_info(pfx, "srtt_minimum_recent");

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

	/* Smoothed rates are not used for now!
	// Look up smoothed maximum download rate first
	double *download_max_rate = lookup_prefix_info(pfx, "download_max_srate");

	if (download_max_rate == NULL || *download_max_rate < EPSILON)
		// If not found or zero: look up maximum download rate (non-smoothoed)
		download_max_rate = lookup_prefix_info(pfx, "download_max_rate");
	*/

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

	/* Smoothed rates are not used for now!
	// Look up smoothed download rate
	double *download_rate = lookup_prefix_info(pfx, "download_srate");

	if (download_rate == NULL || *download_rate < EPSILON)
		// If not found or zero: take download rate (non-smoothoed)
		download_rate = lookup_prefix_info(pfx, "download_rate");
	*/

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

struct src_prefix_list *get_best_prefix(GSList *spl, int filesize, request_context_t *rctx, const char *logfile, strbuf_t *sb)
{
	struct src_prefix_list *chosenpfx = NULL;
	struct src_prefix_list *cur = NULL;

	// Save prefix list for later use
	GSList *spl2 = spl;

	// Go through list of possible source prefixes
	while (spl != NULL)
	{
		cur = spl->data;
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
		double min_completion_time = ((struct eafirst_info *)chosenpfx->policy_info)->predicted_time;
		if (min_completion_time > EPSILON && min_completion_time < DBL_MAX)
		{
			// Set source prefix to the fastest prefix, if link is not overloaded
			strbuf_printf(sb, "\tFastest prefix is on %s (%.2f ms)\n", chosenpfx->if_name, min_completion_time);
			_muacc_logtofile(logfile, "%.2f,%d,%s_fastest\n", min_completion_time, ((struct eafirst_info *)chosenpfx->policy_info)->count, chosenpfx->if_name);
		}
		else
		{
			strbuf_printf(sb, "\tGot completion time of %.2f ms on %s - not taking it\n", min_completion_time, chosenpfx->if_name);
			chosenpfx = get_default_prefix(spl2, rctx, sb);
			_muacc_logtofile(logfile, "%.2f,%d,%s_default\n", min_completion_time, ((struct eafirst_info *)chosenpfx->policy_info)->count, chosenpfx->if_name);
		}
	}
	else
	{
		strbuf_printf(sb, "\tCould not determine fastest prefix\n");
		chosenpfx = get_default_prefix(spl2, rctx, sb);
		_muacc_logtofile(logfile, "0.0,%s_default\n", chosenpfx->if_name);
	}
	return chosenpfx;
}
