#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <err.h>
#include <assert.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <math.h>

#include <glib.h>
#include "mam.h"
#include "mam_pmeasure.h"

#include "lib/muacc_util.h"
#include "lib/dlog.h"

#ifndef MAM_PMEASURE_NOISY_DEBUG0
#define MAM_PMEASURE_NOISY_DEBUG0 1
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG1
#define MAM_PMEASURE_NOISY_DEBUG1 1
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG2
#define MAM_PMEASURE_NOISY_DEBUG2 0
#endif

void compute_srtt(void *pfx, void *data);

/** Print the flow table of every prefix that has one, 
 *  and the mean and median RTTs if they exist
 */
void pmeasure_print_summary(void *pfx, void *data)
{
	struct src_prefix_list *prefix = pfx;

	if (prefix == NULL || prefix->measure_dict == NULL)
		return;

	double *meanvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_mean");
	if (meanvalue != NULL)
		printf("\tMean SRTT: %f ms\n", *meanvalue);

	double *medianvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_median");
	if (medianvalue != NULL)
		printf("\tMedian SRTT: %f ms\n", *medianvalue);

	printf("\n");
}

/** Compute the SRTT on an interface
 *  Insert it into the measure_dict as "srtt_median"
 */
void compute_srtt(void *pfx, void *data)
{
	struct src_prefix_list *prefix = pfx;

	if (prefix == NULL || prefix->measure_dict == NULL)
		return;

	if (prefix->if_name != NULL)
		DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Computing median SRTTs for a prefix of interface %s:\n", prefix->if_name);
	
	// TODO
	DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Not implemented yet.\n");

	return;
}

void pmeasure_setup()
{
	DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Setting up pmeasure \n");
}

void pmeasure_cleanup()
{
	DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Cleaning up\n");
}

void pmeasure_callback(evutil_socket_t fd, short what, void *arg)
{
	mam_context_t *ctx = (mam_context_t *) arg;

	DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Callback invoked.\n");

	if (ctx == NULL)
		return;

	DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Computing SRTTs\n");
	g_slist_foreach(ctx->prefixes, &compute_srtt, NULL);
	if (MAM_PMEASURE_NOISY_DEBUG2)
	{
		DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Printing summary\n");
		g_slist_foreach(ctx->prefixes, &pmeasure_print_summary, NULL);
	}

	DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Callback finished.\n\n");
}
