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

#include "policy_earliest_arrival_base.h"

void choose_this_prefix(struct request_context *rctx, struct src_prefix_list *bind_pfx, strbuf_t *sb)
{
    set_bind_sa(rctx, bind_pfx, sb);
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

	/* Smoothed rates are not used for now!
	// Look up smoothed maximum download rate first
	double *download_max_rate = lookup_prefix_info(pfx, "download_max_srate");

	if (download_max_rate == NULL || *download_max_rate < EPSILON)
		// If not found or zero: look up maximum download rate (non-smoothoed)
		download_max_rate = lookup_prefix_info(pfx, "download_max_rate");
	*/

	double *download_max_rate = lookup_prefix_info(pfx, "download_max_rate");

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

	double *download_rate = lookup_prefix_info(pfx, "download_rate");

	if (download_rate == NULL)
	{
		// If still not found: Return
		strbuf_printf(sb, "download rate:   N/A,   ");
		return -1;
	}

	strbuf_printf(sb, "( download rate: %.2f ) ", *download_rate);

	return *download_rate;
}

/* Compute free capacity on a prefix */
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb)
{
	if (pfx == NULL)
		return -1;

	// Compute free capacity on the link
	double free_capacity = max_rate;

	if (free_capacity < EPSILON)
	{
		strbuf_printf(sb, " Got invalid free capacity: %f\n", free_capacity);
		return -1;
	}

	strbuf_printf(sb, "free capacity = max rate : %.2f\n", free_capacity);

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

    //printf("Maxcapacity: Logging to %s\n", logfile);
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
