/** \file mam_pmeasure.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <err.h>
#include <assert.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <math.h>
#include <time.h>

#include <glib.h>
#include "mam.h"
#include "mam_pmeasure.h"

#include "muacc_util.h"
#include "dlog.h"

#ifndef MAM_PMEASURE_LOGPREFIX
#define MAM_PMEASURE_LOGPREFIX "/tmp/metrics_"
#endif

#ifdef HAVE_LIBNL

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/idiag/idiagnl.h>
#include <netlink/idiag/vegasinfo.h>

#endif /* HAVE_LIBNL */

#ifdef IS_LINUX
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#endif

#undef __USE_MISC // Dirty hack: Prevent breaking previous defines from linux/if.h (included by netlink)
#include <net/if.h>
#define __USE_MISC

#ifndef MAM_PMEASURE_NOISY_DEBUG0
#define MAM_PMEASURE_NOISY_DEBUG0 0
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG1
#define MAM_PMEASURE_NOISY_DEBUG1 0
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG2
#define MAM_PMEASURE_NOISY_DEBUG2 0
#endif

#ifndef MAM_PMEASURE_SRTT_NOISY_DEBUG
#define MAM_PMEASURE_SRTT_NOISY_DEBUG 0
#endif

#ifndef MAM_PMEASURE_THRUPUT_DEBUG
#define MAM_PMEASURE_THRUPUT_DEBUG 0
#endif

#define BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
#define TCPF_ALL 0xFFF

#define MAX_KEY_LENGTH 255

int compare_ip (struct sockaddr *a1, struct sockaddr *a2);
int is_addr_in_pfx (const void *a, const void *b);

void compute_srtt(void *pfx, void *data);
void get_stats(void *iface, void *data);

#ifdef HAVE_LIBNL

#define BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
#define TCPF_ALL 0xFFF

void delete_zeroes(GList **values);
gint compare_rtts (gconstpointer a, gconstpointer b);
void compute_median(GHashTable *dict, GList **values);
void compute_mean(GHashTable *dict, GList *values);
void compute_minimum(GHashTable *dict, GList *values);
void compute_variance(GHashTable *dict, GList *values);
void log_number_of_connections(GHashTable *dict, GList *values);

int rolling_maximum(double *values, int length, double current_maximum);
int rolling_minimum(double *values, int length, double current_minimum);
double calculate_mean(GList *values);
double calculate_median(GList **values);

int create_nl_sock();
GList * parse_nl_msg(struct inet_diag_msg *pMsg, int rtalen, void *pfx, GList *values);
int send_nl_msg(int sock, int i);
int recv_nl_msg(int sock, void *pfx, GList **values);
void insert_errors(GHashTable *pTable, struct rtnl_link *pLink);
#endif

void cleanup_double(void *value);

void cleanup_measure_dict_pf(void *pfx, void *data);
void cleanup_measure_dict_if(void *pfx, void *data);

// The interval in which the computation of the values happens, i.e. the time between two computations (in seconds)
#ifndef CALLBACK_DURATION
static const double CALLBACK_DURATION=0.1;
#endif


long read_stats(char *path);
void compute_link_usage(void *ifc, void *lookup);
int compute_rates (struct iface_list *iface, char *direction);

// Maximum deviation of two values considered "equal"
double EPSILON=0.00001;

// How many values to store until they are overwritten
int n_timeout = 600;

#ifdef IS_LINUX
//path of statistics file (sans interface) in linux broken into two strings
#ifndef path1
static const char path1[] = "/sys/class/net/";
#endif

#ifndef path2
static const char path2[] = "/statistics/";
#endif

long read_stats(char *path);
#endif

#ifndef MAM_PMEASURE_THRUPUT_DEBUG
#define MAM_PMEASURE_THRUPUT_DEBUG 0
#endif

void compute_link_usage(void *ifc, void *lookup);

// Alpha Value for Smoothed RTT Calculation
double alpha = 0.9;

/** compare two ip addresses
 *  return 0 if equal, non-zero otherwise
 */
int compare_ip (struct sockaddr *a1, struct sockaddr *a2)
{
    if (a1->sa_family != a2->sa_family)
        return 1;
    else
    {
        if (a1->sa_family == AF_INET) {
            return memcmp(&((struct sockaddr_in *)a1)->sin_addr, &((struct sockaddr_in *)a2)->sin_addr, sizeof(struct in_addr));; }
        else if (a1->sa_family == AF_INET6)
        {
            return memcmp(&((struct sockaddr_in6 *)a1)->sin6_addr, &((struct sockaddr_in6 *)a2)->sin6_addr, sizeof(struct in6_addr));
        }
    }
    return -1;
}

/** Checks whether a prefix contains a given sockaddr
 *  Returns 0 in this case
 */
int is_addr_in_pfx (const void *a, const void *b)
{
    const struct src_prefix_list *pfx = a;
    const struct sockaddr *addr = b;

    if (pfx == NULL || addr == NULL)
        return -2;

    struct sockaddr_list *addr_list = pfx->if_addrs;

    if (addr_list == NULL)
        return -2;

    for (; addr_list != NULL; addr_list = addr_list->next)
    {
        if (compare_ip((struct sockaddr *)addr, (struct sockaddr *) addr_list->addr) == 0)
            return 0;
    }
    return -1;
}

/** Log the length of the list of RTT values, which corresponds to
*  the number of open TCP connections
*/
void log_number_of_connections(GHashTable *dict, GList *values)
{
    int *num_connections = g_hash_table_lookup(dict, "num_conns");

    if (num_connections == NULL)
    {
        num_connections = malloc(sizeof(int));
        memset(num_connections, 0, sizeof(int));
        g_hash_table_insert(dict, "num_conns", num_connections);
    }

    // Set number of connections to the number of SRTTs in the list
    *num_connections = g_list_length(values);
}

/** Compute the mean SRTT from the currently valid srtts
*  If none, keep the old median SRTT until it expires after n_timeout callbacks
*/
void compute_mean(GHashTable *dict, GList *values)
{
    double *mean_recent = g_hash_table_lookup(dict, "srtt_mean_recent");
    int *current_offset = g_hash_table_lookup(dict, "srtt_mean_timeout_counter");

    if (mean_recent == NULL) {

        mean_recent = malloc(sizeof(double));
        *mean_recent = 0;
        g_hash_table_insert(dict, "srtt_mean_recent", mean_recent);

        current_offset = malloc(sizeof(int));
        *current_offset = 0;
        g_hash_table_insert(dict, "srtt_mean_timeout_counter", current_offset);

        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Inserted mean into measure_dict\n");
    }

    int n = g_list_length(values);

    if (n > 0)
    {
        *mean_recent = calculate_mean(values);
        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "List of length %d has mean value %f \n", n, *mean_recent);
        *current_offset = 0;
    }
    else
    {
        *current_offset = *current_offset + 1;
        if (*current_offset == n_timeout) {
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Mean timed out! Resetting to 0\n");
            *mean_recent = 0;
            *current_offset = 0;
        } else {
            double *minimum = g_hash_table_lookup(dict, "srtt_minimum_recent");
            if (minimum != NULL && (DBL_MAX - *minimum) > 1) {
                DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "No current RTT values. Resetting to minimum %.2f\n", *minimum);
                *mean_recent = *minimum;
            }
            else {
                DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "No current RTT values and no minimum - keeping old mean %.2f\n", *mean_recent);
            }
        }
    }
}

double calculate_mean(GList *values)
{
    double sum_of_values = 0;

    int n = g_list_length(values);

    for (int i = 0; i < n; i++)
    {
        sum_of_values += *(double *) values->data;
        values = values->next;
    }

    return(sum_of_values / n);
}

/** Compute the SRTT variance from the currently valid srtts
*  Insert it into the measure_dict as "srtt_var_across_current"
*/
void compute_variance(GHashTable *dict, GList *values)
{
    double *variance;

    int n = g_list_length(values);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List for interface has length %d\n", n);

    double *meanvalue = g_hash_table_lookup(dict, "srtt_mean_recent");
    if (meanvalue == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "No mean value - cannot compute variance\n");
        return;
    }

    variance = g_hash_table_lookup(dict, "srtt_var_across_current");
    if (variance == NULL)
    {
        variance = malloc(sizeof(double));
        memset(variance, 0, sizeof(double));
        g_hash_table_insert(dict, "srtt_var_across_current", variance);
    }

    if (n == 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "No new RTT values. Setting variance = 0\n");
        *variance = 0;
        return;
    }

    double deviation = 0;
    double sum_of_deviations_squared = 0;
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Mean: %.3f\n", *meanvalue);

    for (int i = 0; i < n; i++)
    {
        deviation = *(double *) values->data - *meanvalue;
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "%d. deviation: %.3f\n", i, deviation);
        sum_of_deviations_squared += deviation * deviation;
        values = values->next;
    }

    *variance = sum_of_deviations_squared / n;
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List of length %d has variance %f \n", n, *variance);
}

/** Delete bogus "zero" RTTs from the list */
void delete_zeroes(GList **values)
{
    GList *current = *values;

    while(current != NULL) {
        double *value = current->data;
        GList *next = current->next;

        if (*value < EPSILON) {
            *values = g_list_remove(*values, value);
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Removed 0 from SRTT list, list now length %d\n", g_list_length(*values));
        }
        current = next;
    }
}

/** Compare function to sort the list */
gint compare_rtts (gconstpointer a, gconstpointer b)
{
    double value1 = *(double *)a;
    double value2 = *(double *)b;
    if (value1 < value2) {
        return -1;
    } else if ((value1 - value2) < 0.00001) {
        return 0;
    } else {
        return 1;
    }
}

/** Compute the median SRTT from a list of individual flows
*  If none, keep the old median SRTT until it expires after n_timeout callbacks
*/
void compute_median(GHashTable *dict, GList **values)
{
    double *median_recent = g_hash_table_lookup(dict, "srtt_median_recent");
    int *current_offset = g_hash_table_lookup(dict, "srtt_median_timeout_counter");

    if (median_recent == NULL) {

        median_recent = malloc(sizeof(double));
        *median_recent = 0;
        g_hash_table_insert(dict, "srtt_median_recent", median_recent);

        current_offset = malloc(sizeof(int));
        *current_offset = 0;
        g_hash_table_insert(dict, "srtt_median_timeout_counter", current_offset);

        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Inserted median into measure_dict\n");
    }

    int n = g_list_length(*values);

    if (n > 0)
    {
        *median_recent = calculate_median(values);
        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Offset %d: List of length %d has median value %f \n", *current_offset, n, *median_recent);
        *current_offset = 0;
    }
    else
    {
        *current_offset = *current_offset + 1;
        if (*current_offset == n_timeout)
        {
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Median timed out! Resetting to 0\n");
            *median_recent = 0;
            *current_offset = 0;
        } else {
            double *minimum = g_hash_table_lookup(dict, "srtt_minimum_recent");
            if (minimum != NULL && (DBL_MAX - *minimum > 1) ) {
                DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "No current RTT values. Resetting to minimum %.2f\n", *minimum);
                *median_recent = *minimum;
            }
            else {
                DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "No current RTT values and no minimum - keeping old median %.2f\n", *median_recent);
            }
        }
    }
}

double calculate_median(GList **values)
{
    double medianvalue = 0;

    *values = g_list_sort(*values, *compare_rtts);
    int n = g_list_length(*values);

    if (n == 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "No RTT values. Cannot compute median.\n");
    }
    else if (n % 2)
    {
        // odd number of elements
        medianvalue = *(double *) g_list_nth_data(*values, (n/2));
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "New median is %f (element index %d)\n", medianvalue, (n/2));
    }
    else
    {
        // even number of elements
        double val1 = *(double *) g_list_nth_data(*values, (n/2)-1);
        double val2 = *(double *) g_list_nth_data(*values, (n/2));
        medianvalue = (val1 + val2) / 2;
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "New median is %f (intermediate value between element index %d (%f) and element index %d (%f))\n", medianvalue, (n-1)/2, val1, (n+1)/2, val2);
    }
    return medianvalue;
}

/** Keep a rolling minimum of the SRTTs seen in the last n_timeout callbacks
*/
void compute_minimum(GHashTable *dict, GList *values)
{
    double *minimum_values = g_hash_table_lookup(dict, "srtt_minimum_values");
    double *minimum_recent = g_hash_table_lookup(dict, "srtt_minimum_recent");
    double *minimum_current = g_hash_table_lookup(dict, "srtt_minimum_current");
    int *minimum_offset = g_hash_table_lookup(dict, "srtt_minimum_recent_offset");
    int *current_offset = g_hash_table_lookup(dict, "srtt_minimum_current_offset");

    if (minimum_values == NULL) {

        minimum_values = malloc(n_timeout * sizeof(double));
        memset(minimum_values, 0, n_timeout * sizeof(double));
        g_hash_table_insert(dict, "srtt_minimum_values", minimum_values);

        minimum_recent = malloc(sizeof(double));
        *minimum_recent = DBL_MAX;
        g_hash_table_insert(dict, "srtt_minimum_recent", minimum_recent);

        minimum_current = malloc(sizeof(double));
        *minimum_current = DBL_MAX;
        g_hash_table_insert(dict, "srtt_minimum_current", minimum_current);

        minimum_offset = malloc(sizeof(int));
        *minimum_offset = 0;
        g_hash_table_insert(dict, "srtt_minimum_recent_offset", minimum_offset);

        current_offset = malloc(sizeof(int));
        *current_offset = 0;
        g_hash_table_insert(dict, "srtt_minimum_current_offset", current_offset);

        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Inserted minimum into measure_dict\n");
    }

    int n = g_list_length(values);

    if (n == 0)
    {
        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "[offset %d] No new RTT values. Keeping old minimum at offset %d\n", *current_offset, *minimum_offset);
        *minimum_current = DBL_MAX;
    }
    else
    {
        // List is sorted because compute_median() was called earlier
        // --> first element is minimum
        *minimum_current = *(double *) g_list_first(values)->data;

        // Check if minimum is almost zero - if there's more values, use them
        if (*minimum_current < EPSILON && n > 1) {
            GList *min_candidate = values;
            while (min_candidate != NULL) {
                GList *next = min_candidate->next;
                *minimum_current = *(double *) min_candidate->data;
                if (*minimum_current > EPSILON) {
                   break;
                }
                min_candidate = next;
            }
        }
        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "[offset %d] Got current minimum %f, comparing against recent minimum %f at offset %d\n", *current_offset, *minimum_current, *minimum_recent, *minimum_offset);
        if (*minimum_current < *minimum_recent && *minimum_current > EPSILON)
        {
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Found new minimum value: %f \n", *minimum_current);
            *minimum_recent = *minimum_current;
            *minimum_offset = *current_offset;
        }
        else
        {
            if (*current_offset == *minimum_offset) {
                // Same offset reached again - Minimum timed out! Need new.
                *minimum_offset = rolling_minimum(minimum_values, n_timeout, *minimum_recent);
                if (*minimum_offset == -1) {
                    DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Minimum timed out - did not manage to get a new one. Falling back to DBL_MAX\n");
                    *minimum_offset = *current_offset;
                    *minimum_recent = DBL_MAX;
                }
                else
                {
                    *minimum_recent = minimum_values[*minimum_offset];
                    DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Minimum timed out - got new minimum %f at offset %d\n", *minimum_recent, *minimum_offset);
                }
            } else {
                DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Keeping old minimum value %f \n", *minimum_recent);
            }
        }
    }

    minimum_values[*current_offset] = *minimum_current;
    *current_offset = *current_offset + 1;
    if (*current_offset == n_timeout)
        *current_offset = 0;

}

/* Get the position of the maximum in an array of values */
int rolling_maximum(double *values, int length, double old_maximum)
{
    double candidate = values[0];
    int candidate_offset = 0;

    for (int i=1; i<length; i++) {
        if ((old_maximum - values[i] < EPSILON) && (old_maximum - values[i] > -EPSILON)) {
            // Found another occurence of the old maximum value - return its offset
            return i;
        }
        // Found a new candidate for the maximum - store its offset
        if (values[i] > candidate) {
            candidate = values[i];
            candidate_offset = i;
        }
    }
    // End of array - return offset of current candidate for maximum
    return candidate_offset;
}

/* Get the position of the (non-zero) minimum in an array of values
* !!! Returns -1 if there is none !!!
*/
int rolling_minimum(double *values, int length, double old_minimum)
{
    double candidate = DBL_MAX;
    int candidate_offset = -1;

    for (int i=0; i<length; i++) {
        if ((old_minimum - values[i] < EPSILON) && (old_minimum - values[i] > -EPSILON)) {
            // Found another occurence of the old minimum value - return its offset
            return i;
        }
        // Found a new candidate for the minimum - store its offset
        if (values[i] > 0 && values[i] < candidate) {
            candidate = values[i];
            candidate_offset = i;
        }
    }
    // End of array - return offset of current candidate for minimum
    return candidate_offset;
}


void insert_errors(GHashTable *dict, struct rtnl_link *link)
{
    uint64_t *tx_errors;
    uint64_t *rx_errors;

    tx_errors = g_hash_table_lookup(dict, "tx_errors");
    rx_errors = g_hash_table_lookup(dict, "rx_errors");

    if (tx_errors == NULL)
    {
        tx_errors = malloc(sizeof(uint64_t));
        memset(tx_errors, 0, sizeof(uint64_t));
        g_hash_table_insert(dict, "tx_errors", tx_errors);
    }

    if (rx_errors == NULL)
    {
        rx_errors = malloc(sizeof(uint64_t));
        memset(rx_errors, 0, sizeof(uint64_t));
        g_hash_table_insert(dict, "rx_errors", rx_errors);
    }

    *tx_errors = rtnl_link_get_stat(link,RTNL_LINK_TX_ERRORS);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2,"Added %" PRIu64 " as TX_ERRORS\n", *tx_errors);
    *rx_errors = rtnl_link_get_stat(link,RTNL_LINK_RX_PACKETS);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Added %" PRIu64 " as RX_ERRORS\n", *rx_errors);
}
#endif

/** Print the available measurement data for each prefix */
void pmeasure_print_prefix_summary(void *pfx, void *data)
{
    struct src_prefix_list *prefix = pfx;

    if (prefix == NULL || prefix->measure_dict == NULL || !strncmp(prefix->if_name,"lo",2))
        return;
    printf("Summary for prefix on interface %s, Family: %s\n", prefix->if_name, prefix->family == AF_INET?"IPv4":"IPv6");
    double *meanvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_mean_recent");
    if (meanvalue != NULL)
        printf("\tMean SRTT: %f ms\n", *meanvalue);

    double *variation = g_hash_table_lookup(prefix->measure_dict, "srtt_var_across_current");
    if (variation != NULL)
        printf("\tSRTT variation: %f ms\n", *variation);

    double *medianvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_median_recent");
    if (medianvalue != NULL)
        printf("\tMedian SRTT: %f ms\n", *medianvalue);

    double *srtt_vars = g_hash_table_lookup(prefix->measure_dict, "srtt_var_median_within");
    if (srtt_vars != NULL)
        printf("\tMedian of variations of SRTTs: %f ms\n", *srtt_vars);

    srtt_vars = g_hash_table_lookup(prefix->measure_dict, "srtt_var_mean_within");
    if (srtt_vars != NULL)
        printf("\tMean of variations of SRTTs: %f ms\n", *srtt_vars);



    printf("\n");
}

void pmeasure_print_iface_summary(void *ifc, void *data)
{
    struct iface_list *iface = ifc;

    if (iface == NULL || iface->measure_dict == NULL || !strncmp(iface->if_name,"lo",2))
        return;

    printf("Summary for interface %s\n", iface->if_name);

    double *download_rate = g_hash_table_lookup(iface->measure_dict, "download_rate_current");
    if (download_rate != NULL)
        printf("\tCurrent download rate: \t\t\t%f Bytes/s \n", *download_rate);

    double *download_max_rate = g_hash_table_lookup(iface->measure_dict, "download_rate_max_recent");
    if (download_max_rate != NULL)
        printf("\tRecent download maximal rate: \t\t%f Bytes/s (last %d values)\n", *download_max_rate, n_timeout);

    double *upload_rate = g_hash_table_lookup(iface->measure_dict, "upload_rate_current");
    if (upload_rate != NULL)
        printf("\tUpload rate: \t\t\t%f Bytes/s \n", *upload_rate);

    double *upload_max_rate = g_hash_table_lookup(iface->measure_dict, "upload_rate_max_recent");
    if (upload_max_rate != NULL)
        printf("\tUpload maximal rate: \t\t%f Bytes/s (last %d values)\n", *upload_max_rate, n_timeout);

    uint64_t  *rx_errors = g_hash_table_lookup(iface->measure_dict, "rx_errors");
    if (rx_errors != NULL)
        printf("\tRX Errors: %" PRIu64 " \n", *rx_errors);

    uint64_t *tx_errors = g_hash_table_lookup(iface->measure_dict, "tx_errors");
    if (tx_errors != NULL)
        printf("\tTX Errors: %" PRIu64 " \n", *tx_errors);




    uint16_t *numsta = g_hash_table_lookup(iface->measure_dict, "number_of_stations");
    if (numsta != NULL)
        printf("\tNumber of stations: \t\t%" PRIu16 " \n", *numsta);

    double *channelutilization = g_hash_table_lookup(iface->measure_dict, "channel_utilization");
    if (channelutilization != NULL)
        printf("\tChannel utilization: \t\t%.2f%% \n", *channelutilization);

    uint16_t *adcap = g_hash_table_lookup(iface->measure_dict, "available_admission_capacity");
    if (adcap != NULL)
        printf("\tAvailable admission capacity: \t%" PRIu16 " \n", *adcap);

    printf("\n");
}

/** Log the available measurement data for each prefix, with timestamp and first prefix address
    Destination: MAM_PMEASURE_LOGPREFIXprefix.log
*/
void pmeasure_log_prefix_summary(void *pfx, void *data)
{
    struct src_prefix_list *prefix = pfx;

    if (prefix == NULL || prefix->measure_dict == NULL || !strncmp(prefix->if_name,"lo",2))
        return;

    // Put together logfile name
    char *logfile;
    asprintf(&logfile, "%sprefix.log", MAM_PMEASURE_LOGPREFIX);

    double *measurement_timestamp_sec = g_hash_table_lookup(prefix->measure_dict,"srtt_timestamp_sec");
    double *measurement_timestamp_usec = g_hash_table_lookup(prefix->measure_dict,"srtt_timestamp_usec");

    if (measurement_timestamp_sec != NULL && measurement_timestamp_usec != NULL)
        _muacc_logtofile(logfile, "%.0f.%06.0f,", *measurement_timestamp_sec, *measurement_timestamp_usec);
    else
        _muacc_logtofile(logfile, "NA,");

    // Construct string to print the first address of this prefix into
    char addr_str[INET6_ADDRSTRLEN+1];

    // Print first address of the prefix to the string, then print string to logfile
    if (prefix->family == AF_INET)
    {
        inet_ntop(AF_INET, &( ((struct sockaddr_in *) (prefix->if_addrs->addr))->sin_addr ), addr_str, sizeof(addr_str));
    }
    else if (prefix->family == AF_INET6)
    {
        inet_ntop(AF_INET6, &( ((struct sockaddr_in6 *) (prefix->if_addrs->addr))->sin6_addr ), addr_str, sizeof(addr_str));
    }
    _muacc_logtofile(logfile,"%s,", addr_str);

    // Log interface name that this prefix belongs to
    _muacc_logtofile(logfile, "%s,", prefix->if_name);

    double *meanvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_mean_recent");
    if (meanvalue != NULL)
        _muacc_logtofile(logfile, "%f,", *meanvalue);
    else
        _muacc_logtofile(logfile, "NA,");

    double *variation = g_hash_table_lookup(prefix->measure_dict, "srtt_var_across_current");
    if (variation != NULL)
        _muacc_logtofile(logfile, "%f,", *variation);
    else
        _muacc_logtofile(logfile, "NA,");

    double *medianvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_median_recent");
    if (medianvalue != NULL)
        _muacc_logtofile(logfile, "%f,", *medianvalue);
    else
        _muacc_logtofile(logfile, "NA,");

    double *minimumvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_minimum_recent");
    if (minimumvalue != NULL && *minimumvalue < DBL_MAX)
        _muacc_logtofile(logfile, "%f,", *minimumvalue);
    else
        _muacc_logtofile(logfile, "NA,");

    double *var_of_srtts = g_hash_table_lookup(prefix->measure_dict, "srtt_var_median_within");
    if (var_of_srtts != NULL)
        _muacc_logtofile(logfile, "%f,", *var_of_srtts);
    else
        _muacc_logtofile(logfile, "NA,");

    var_of_srtts = g_hash_table_lookup(prefix->measure_dict, "srtt_var_mean_within");
    if (var_of_srtts != NULL)
        _muacc_logtofile(logfile, "%f,", *var_of_srtts);
    else
        _muacc_logtofile(logfile, "NA,");

    int *num_conns = g_hash_table_lookup(prefix->measure_dict, "num_conns");
    if (num_conns != NULL)
        _muacc_logtofile(logfile, "%d\n", *num_conns);
    else
        _muacc_logtofile(logfile, "NA\n");

    free(logfile);
}


/** Log the available measurement data for each interface, with timestamp
    Destination: MAM_PMEASURE_LOGPREFIXinterface.log
*/
void pmeasure_log_iface_summary(void *ifc, void *data)
{
    struct iface_list *iface = ifc;

    if (iface == NULL || iface->measure_dict == NULL || !strncmp(iface->if_name,"lo",2))
        return;

    // Put together logfile name
    char *logfile;
    asprintf(&logfile, "%sinterface.log", MAM_PMEASURE_LOGPREFIX);

    double *measurement_timestamp_sec = g_hash_table_lookup(iface->measure_dict,"rate_timestamp_sec");
    double *measurement_timestamp_usec = g_hash_table_lookup(iface->measure_dict,"rate_timestamp_usec");

    if (measurement_timestamp_sec != NULL && measurement_timestamp_usec != NULL)
        _muacc_logtofile(logfile, "%.0f.%06.0f,", *measurement_timestamp_sec, *measurement_timestamp_usec);
    else
        _muacc_logtofile(logfile, "NA,");

    // Log interface name
    _muacc_logtofile(logfile, "%s,", iface->if_name);

    double *download_rate = g_hash_table_lookup(iface->measure_dict, "download_rate_current");
    if (download_rate != NULL)
        _muacc_logtofile(logfile, "%f,", *download_rate);
    else
        _muacc_logtofile(logfile, "NA,");

    double *download_max_rate = g_hash_table_lookup(iface->measure_dict, "download_rate_max_recent");
    if (download_max_rate != NULL)
        _muacc_logtofile(logfile, "%f,", *download_max_rate);
    else
        _muacc_logtofile(logfile, "NA,");

    double *upload_rate = g_hash_table_lookup(iface->measure_dict, "upload_rate_current");
    if (upload_rate != NULL)
        _muacc_logtofile(logfile, "%f,", *upload_rate);
    else
        _muacc_logtofile(logfile, "NA,");

    double *upload_max_rate = g_hash_table_lookup(iface->measure_dict, "upload_rate_max_recent");
    if (upload_max_rate != NULL)
        _muacc_logtofile(logfile, "%f,", *upload_max_rate);
    else
        _muacc_logtofile(logfile, "NA,");

    long *upload_counter = g_hash_table_lookup(iface->measure_dict, "upload_counter");
    if (upload_counter != NULL)
        _muacc_logtofile(logfile, "%ld,", *upload_counter);
    else
        _muacc_logtofile(logfile, "NA,");

    long *download_counter = g_hash_table_lookup(iface->measure_dict, "download_counter");
    if (download_counter != NULL)
        _muacc_logtofile(logfile, "%ld,", *download_counter);
    else
        _muacc_logtofile(logfile, "NA,");

    uint64_t  *rx_errors = g_hash_table_lookup(iface->measure_dict, "rx_errors");
    if (rx_errors != NULL)
        _muacc_logtofile(logfile, "%" PRIu64 ",", *rx_errors);
    else
        _muacc_logtofile(logfile, "NA,");

    uint64_t *tx_errors = g_hash_table_lookup(iface->measure_dict, "tx_errors");
    if (tx_errors != NULL)
        _muacc_logtofile(logfile, "%" PRIu64 ",", *tx_errors);
    else
        _muacc_logtofile(logfile, "NA,");

    uint16_t *numsta = g_hash_table_lookup(iface->measure_dict, "number_of_stations");
    if (numsta != NULL)
        _muacc_logtofile(logfile, "%" PRIu16 ",", *numsta);
    else
        _muacc_logtofile(logfile, "NA,");

    double *channelutilization = g_hash_table_lookup(iface->measure_dict, "channel_utilization");
    if (channelutilization != NULL)
        _muacc_logtofile(logfile, "%.2f,", *channelutilization);
    else
        _muacc_logtofile(logfile, "NA,");

    uint16_t *adcap = g_hash_table_lookup(iface->measure_dict, "available_admission_capacity");
    if (adcap != NULL)
        _muacc_logtofile(logfile, "%" PRIu16 "\n", *adcap);
    else
        _muacc_logtofile(logfile, "NA\n");

    free(logfile);
}

#ifdef HAVE_LIBNL
int create_nl_sock()
{
	int sock = 0;

	if ((sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) ==-1)
	{
		perror("socket error");
		return EXIT_FAILURE;
	}
	return sock;
}

/*
 * Build and send a Netlink Request Message for the af - Family
 * on the given Socket.
 *
 * Returns the number of bytes sent, or -1 for errors.
 * */
int send_nl_msg(int sock, int af)
{
    // initialize structures
    struct msghdr msg;                 // Message structure
    struct nlmsghdr nlh;               // Netlink Message Header
    struct sockaddr_nl sa;             // Socket address
    struct iovec iov[4];               // vector for information
    struct inet_diag_req_v2 request;   // Request structure
    int ret = 0;

    // set structures to 0
    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&nlh, 0, sizeof(nlh));
    memset(&request, 0, sizeof(request));

    // build the message
    sa.nl_family           = AF_NETLINK;
    request.sdiag_family   = af;
    request.sdiag_protocol = IPPROTO_TCP;

    // We're interested in all TCP Sockets except Sockets
    // in the states TCP_SYN_SENT, TCP_SYN_RECV, TCP_TIME_WAIT and TCP_CLOSE
    request.idiag_states = TCPF_ALL & ~((1<<TCP_SYN_SENT) | (1<<TCP_SYN_RECV) | (1<<TCP_TIME_WAIT) | (1<<TCP_CLOSE));

    // Request tcp_info struct
    request.idiag_ext |= (1 << (INET_DIAG_INFO - 1));

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(request));

    // set message flags
    // note: NLM_F_MATCH is not working due to a bug,
    //       we have to do the filtering manual
    nlh.nlmsg_flags = NLM_F_MATCH | NLM_F_REQUEST;

    // Compose message
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    iov[0].iov_base = (void*) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void*) &request;
    iov[1].iov_len = sizeof(request);

    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    //send the message
    ret = sendmsg(sock, &msg, 0);
    return ret;
}

/*
 * Receives Netlink Messages on the given Socket
 * and calls the parse_nl_msg() method to parse
 * the RTT values and add it to the values list
 *
 * Returns 0 on success and 1 on failure
 * */
int recv_nl_msg(int sock, void *pfx, GList **values)
{
    int numbytes = 0, rtalen =0;
    struct nlmsghdr *nlh;
    uint8_t msg_buf[BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;
    struct timeval timeout;
    timeout.tv_sec = CALLBACK_DURATION;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(struct timeval));

    while (1)
    {
        // receive the message
        numbytes = recv(sock, msg_buf, sizeof(msg_buf), 0);
        if (numbytes < 0) {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1,"Error receiving netlink message\n");
            return EXIT_FAILURE;
        }
        nlh = (struct nlmsghdr*) msg_buf;

        while (NLMSG_OK(nlh, numbytes))
        {
            // received last message
            if (nlh->nlmsg_type == NLMSG_DONE)
                return EXIT_SUCCESS;

            // Error in message
            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                DLOG(MAM_PMEASURE_NOISY_DEBUG1,"Error in netlink Message\n");
                return EXIT_FAILURE;
            }

            diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
            // Attributes
            rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));

            // parse the message
            *values = parse_nl_msg(diag_msg, rtalen, pfx, *values);

            // get the next message
            nlh = NLMSG_NEXT(nlh, numbytes);
        }
    }
    return EXIT_SUCCESS;
}

/*
 * Parses a Netlink Message and add the RTT values to the values list
 *
 * */
GList * parse_nl_msg(struct inet_diag_msg *msg, int rtalen, void *pfx, GList *values)
{

    // structure for attributes
    struct rtattr *attr;
    struct tcp_info *tcpInfo;
    // sockaddr structure for prefix sockets
    struct sockaddr_in msg_addr_v4;
    struct sockaddr_in6 msg_addr_v6;
    struct src_prefix_list *prefix = pfx;

    char address[INET6_ADDRSTRLEN];
    memset(&address, 0, sizeof(address));

    if(msg->idiag_family == AF_INET)
    {
        msg_addr_v4.sin_family = msg->idiag_family;
        msg_addr_v4.sin_port = msg->id.idiag_sport;
        inet_ntop(AF_INET, &(msg->id.idiag_src), address, INET_ADDRSTRLEN);
        inet_pton(AF_INET, address, &(msg_addr_v4.sin_addr));

    } else if(msg->idiag_family == AF_INET6)
    {
        msg_addr_v6.sin6_family = AF_INET6;
        msg_addr_v6.sin6_port = msg->id.idiag_sport;
        inet_ntop(AF_INET6, (struct in_addr6 *) &(msg->id.idiag_src), address, INET6_ADDRSTRLEN);
        inet_pton(AF_INET6, address,  &(msg_addr_v6.sin6_addr));
    }

    // Find the right Socket
    switch(msg->idiag_family)
    {
        case(AF_INET6):
        {
            if ( (is_addr_in_pfx(pfx, &msg_addr_v6) != 0))
                return values;
            break;
        }
        case(AF_INET):
        {
            if ( (is_addr_in_pfx(pfx, &msg_addr_v4) != 0))
                return values;
            break;
        }
        default: return values;
    }

    GList *var_table = g_hash_table_lookup(prefix->measure_dict, "vars_of_rtts");
    GList *values2 = var_table;


    // Get Attributes
    if (rtalen > 0)
    {
        attr = (struct rtattr*) (msg+1);

        while (RTA_OK(attr, rtalen))
        {
            if (attr->rta_type == INET_DIAG_INFO)
            {
                // Get rtt values
                tcpInfo = (struct tcp_info*) RTA_DATA(attr);
                double *rtt = malloc(sizeof(double));
                *rtt = tcpInfo->tcpi_rtt/1000.;

                double *rtt_var = malloc(sizeof(double));
                *rtt_var = tcpInfo->tcpi_rttvar/1000.;

                // append it to the list of values
                values = g_list_append(values, rtt);
                values2 = g_list_append(values2, rtt_var);
            }
            //Get next attributes
            attr = RTA_NEXT(attr, rtalen);
        }
    }

    if (var_table == NULL) {
        g_hash_table_insert(prefix->measure_dict, "vars_of_rtts", values2);
        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Inserted vars_of_rtts\n");
    }

    return values;
}
#endif /* HAVE_LIBNL */

/** Compute the SRTT on an prefix, except on lo
*  Insert it into the measure_dict as "srtt_median_recent"
*/
void compute_srtt(void *pfx, void *data)
{
    struct src_prefix_list *prefix = pfx;

    // List for rtt values
    GList *values = NULL;

    if (prefix == NULL || prefix->measure_dict == NULL)
        return;


    if (prefix->if_name != NULL && strncmp(prefix->if_name,"lo",2))
    {
        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Computing SRTTs for a prefix of interface %s:\n", prefix->if_name);

        #ifdef HAVE_LIBNL
        // create the socket
        int sock_ip4 = create_nl_sock();
        int sock_ip6 = create_nl_sock();

        if (sock_ip4 == EXIT_FAILURE || sock_ip6 == EXIT_FAILURE)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Socket creation failed\n");

        // Create and send netlink messages
        // we have to send two different requests, the first time
        // with the IPv4 Flag and the other time with the IPv6 flag
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Sending IPv4 Request\n");
        if (send_nl_msg(sock_ip4, AF_INET) == -1)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, " Error sending Netlink Request\n");

        // receive messages
        if (recv_nl_msg(sock_ip4, prefix, &values) != 0)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error receiving Netlink Messages\n")

        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Sending IPv6 Request\n");
        if (send_nl_msg(sock_ip6, AF_INET6) == -1)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, " Error sending Netlink Request\n");

        if (recv_nl_msg(sock_ip6, prefix, &values) != 0)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error receiving Netlink Messages\n");

        delete_zeroes(&values);
        log_number_of_connections(prefix->measure_dict, values);

        // compute mean, median and minimum out of the
        // rtt values and write it into the dict
        compute_mean(prefix->measure_dict, values);
        compute_median(prefix->measure_dict, &values);
        compute_minimum(prefix->measure_dict, values);
        compute_variance(prefix->measure_dict, values);

        GList *vars_of_rtts = g_hash_table_lookup(prefix->measure_dict, "vars_of_rtts");
        double *median_of_vars = g_hash_table_lookup(prefix->measure_dict, "srtt_var_median_within");
        double *mean_of_vars = g_hash_table_lookup(prefix->measure_dict, "srtt_var_mean_within");
        if (mean_of_vars == NULL || median_of_vars == NULL)
        {
            median_of_vars = malloc(sizeof(double));
            mean_of_vars = malloc(sizeof(double));
            g_hash_table_insert(prefix->measure_dict, "srtt_var_median_within", median_of_vars);
            g_hash_table_insert(prefix->measure_dict, "srtt_var_mean_within", mean_of_vars);
        }

        if (vars_of_rtts != NULL) {
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Got vars_of_rtts %p\n", vars_of_rtts);
            *median_of_vars = calculate_median(&vars_of_rtts);
            *mean_of_vars = calculate_mean(vars_of_rtts);
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Computed median of vars: %f and mean: %f\n", *median_of_vars, *mean_of_vars);
        } else {
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Got no vars_of_rtts - setting median and mean to zero.\n");
            *median_of_vars = 0;
            *mean_of_vars = 0;
        }


        // clean up
        g_list_free_full(values, &cleanup_double);
        g_list_free_full(vars_of_rtts, &cleanup_double);
        g_hash_table_remove(prefix->measure_dict, "vars_of_rtts");
        close(sock_ip4);
        close(sock_ip6);
        #endif

        // Get timestamp and log it
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        double *measurement_timestamp_sec = g_hash_table_lookup(prefix->measure_dict,"srtt_timestamp_sec");
        double *measurement_timestamp_usec = g_hash_table_lookup(prefix->measure_dict,"srtt_timestamp_usec");

        if (measurement_timestamp_sec == NULL || measurement_timestamp_usec == NULL)
        {
            measurement_timestamp_sec = malloc(sizeof(double));
            memset(measurement_timestamp_sec, 0, sizeof(double));
            g_hash_table_insert(prefix->measure_dict, "srtt_timestamp_sec", measurement_timestamp_sec);
            *measurement_timestamp_sec = current_time.tv_sec;

            measurement_timestamp_usec = malloc(sizeof(double));
            memset(measurement_timestamp_usec, 0, sizeof(double));
            g_hash_table_insert(prefix->measure_dict, "srtt_timestamp_usec", measurement_timestamp_usec);
            *measurement_timestamp_usec = current_time.tv_usec;
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG,"Logged new timestamp %f.%f\n",*measurement_timestamp_sec, *measurement_timestamp_usec);
        }
        else
        {
            *measurement_timestamp_usec = current_time.tv_usec;
            *measurement_timestamp_sec = current_time.tv_sec;
            DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG,"Logged timestamp %6.0f.%06.0f\n",*measurement_timestamp_sec, *measurement_timestamp_usec);
        }
    }

    return;
}

#ifdef HAVE_LIBNL
/*
 * Get TCP Statistics like TX_ERRORS and RX_ERRORS
 * of an Interface and insert it into the measure_dict
 *
 * */
void get_stats(void *iface, void *data)
{
    struct nl_sock *sock;
    struct nl_cache *cache;
    struct rtnl_link *link;

    struct iface_list *interface = iface;

    if (interface == NULL || interface->measure_dict == NULL)
        return;

    // Allocate Socket
    sock = nl_socket_alloc();

    if (!sock)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error creating Socket\n");
        return;
    }
    // connect Socket
    if(nl_connect(sock, NETLINK_ROUTE) < 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error connecting Socket\n");
        return;
    }
    // Allocate Link Cache
    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) <0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error allocating Link cache\n");
        nl_socket_free(sock);
        return;
    }
    // Get Interface by name
    if (!(link = rtnl_link_get_by_name(cache, interface->if_name)))
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error getting Interface\n");
        return;
    }

    insert_errors(interface->measure_dict, link);

    // clean up
    rtnl_link_put(link);
    nl_cache_put(cache);
    nl_socket_free(sock);
}
#endif

void cleanup_double(void *value) {
    double *tofree = value;
    free(tofree);
}

{


}

{















    }

    }






}

{

    g_hash_table_remove(iface->measure_dict, "signal_strength");
    g_hash_table_remove(iface->measure_dict, "signal_strength_avg");
    g_hash_table_remove(iface->measure_dict, "signal_strength_bss");
    g_hash_table_remove(iface->measure_dict, "rx_rate");
    g_hash_table_remove(iface->measure_dict, "tx_rate");
    g_hash_table_remove(iface->measure_dict, "number_of_stations");
    g_hash_table_remove(iface->measure_dict, "channel_utilization");
    g_hash_table_remove(iface->measure_dict, "available_admission_capacity");
}

{

}

{






void cleanup_measure_dict_pf(void *pfx, void *data)
{
    struct src_prefix_list *prefix = pfx;
    if (pfx == NULL || prefix->if_name == NULL || prefix->measure_dict == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Cannot cleanup measure dict for NULL network prefix\n");
        return;
    }

    double *meanvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_mean_recent");
    if (meanvalue != NULL)
        free(meanvalue);

    double *medianvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_median_recent");
    if (medianvalue != NULL)
        free(medianvalue);

    double *minimumvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_minimum_recent");
    if (minimumvalue != NULL)
        free(minimumvalue);

    minimumvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_minimum_current");
    if (minimumvalue != NULL)
        free(minimumvalue);

    minimumvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_minimum_values");
    if (minimumvalue != NULL)
        free(minimumvalue);

    int *offset = g_hash_table_lookup(prefix->measure_dict, "srtt_minimum_recent_offset");
    if (offset != NULL)
        free(offset);

    offset = g_hash_table_lookup(prefix->measure_dict, "srtt_minimum_current_offset");
    if (offset != NULL)
        free(offset);

    offset = g_hash_table_lookup(prefix->measure_dict, "srtt_mean_timeout_counter");
    if (offset != NULL)
        free(offset);

    offset = g_hash_table_lookup(prefix->measure_dict, "srtt_median_timeout_counter");
    if (offset != NULL)
        free(offset);

    double *variation = g_hash_table_lookup(prefix->measure_dict, "srtt_var_across_current");
    if (variation != NULL)
        free(variation);

    double *var_of_srtts = g_hash_table_lookup(prefix->measure_dict, "srtt_var_median_within");
    if (var_of_srtts != NULL)
        free(var_of_srtts);

    var_of_srtts = g_hash_table_lookup(prefix->measure_dict, "srtt_var_mean_within");
    if (var_of_srtts != NULL)
        free(var_of_srtts);

    double *packet_loss = g_hash_table_lookup(prefix->measure_dict, "packet_loss_up_median");
    if (packet_loss != NULL)
        free(packet_loss);

    int *num_conns = g_hash_table_lookup(prefix->measure_dict, "num_conns");
    if (num_conns != NULL)
        free(num_conns);

    double *measurement_timestamp_sec = g_hash_table_lookup(prefix->measure_dict, "srtt_timestamp_sec");
    if (measurement_timestamp_sec != NULL)
        free(measurement_timestamp_sec);

    double *measurement_timestamp_usec = g_hash_table_lookup(prefix->measure_dict, "srtt_timestamp_usec");
    if (measurement_timestamp_usec != NULL)
        free(measurement_timestamp_usec);


}

void cleanup_measure_dict_if(void *ifc, void *data)
{
    struct iface_list *iface = ifc;
    if (ifc == NULL || iface->if_name == NULL || iface->measure_dict == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Cannot cleanup measure dict for NULL network interface\n");
        return;
    }

    int *offset = g_hash_table_lookup(iface->measure_dict, "upload_rate_offset");
    if (offset != NULL)
        free(offset);

    offset = g_hash_table_lookup(iface->measure_dict, "download_rate_offset");
    if (offset != NULL)
        free(offset);

    offset = g_hash_table_lookup(iface->measure_dict, "upload_rate_max_offset");
    if (offset != NULL)
        free(offset);

    offset = g_hash_table_lookup(iface->measure_dict, "download_rate_max_offset");
    if (offset != NULL)
        free(offset);

    long *bytes = g_hash_table_lookup(iface->measure_dict, "upload_counter");
    if (bytes != NULL)
        free(bytes);

    bytes = g_hash_table_lookup(iface->measure_dict, "download_counter");
    if (bytes != NULL)
        free(bytes);

    double *rate = g_hash_table_lookup(iface->measure_dict, "download_rate_current");
    if (rate != NULL)
        free(rate);

    rate = g_hash_table_lookup(iface->measure_dict, "download_rate_max_recent");
    if (rate != NULL)
        free(rate);

    rate = g_hash_table_lookup(iface->measure_dict, "upload_rate_current");
    if (rate != NULL)
        free(rate);

    rate = g_hash_table_lookup(iface->measure_dict, "upload_rate_max_recent");
    if (rate != NULL)
        free(rate);

    rate = g_hash_table_lookup(iface->measure_dict, "download_values");
    if (rate != NULL)
        free(rate);

    rate = g_hash_table_lookup(iface->measure_dict, "upload_values");
    if (rate != NULL)
        free(rate);

    double *measurement_timestamp_sec = g_hash_table_lookup(iface->measure_dict, "rate_timestamp_sec");
    if (measurement_timestamp_sec != NULL)
        free(measurement_timestamp_sec);

    double *measurement_timestamp_usec = g_hash_table_lookup(iface->measure_dict, "rate_timestamp_usec");
    if (measurement_timestamp_usec != NULL)
        free(measurement_timestamp_usec);

    uint64_t  *rx_errors = g_hash_table_lookup(iface->measure_dict, "rx_errors");
    if (rx_errors != NULL) {
        free(rx_errors);
    }

    uint64_t *tx_errors = g_hash_table_lookup(iface->measure_dict, "tx_errors");
    if (tx_errors != NULL) {
        free(tx_errors);
    }
}

/**
*This function reads reads the interface counters for each interface called.
*/
long read_stats(char *path)
{
    FILE *fp;
    long curr_counter = 0;

    fp = fopen((const char *)path,"r");

    if (fp == NULL)
    {    DLOG(MAM_PMEASURE_THRUPUT_DEBUG, "\nError Reading stats file\n");
        perror(path);
        return 0;
    }
    fscanf(fp,"%ld",&curr_counter);
    fclose(fp);
    return curr_counter;
}

/** Compute the rates for one interface in one direction
*  First the current rate, based on the counter increase / passed time
*  then the maximum rate seen in the last n_timeout callbacks
*/
int compute_rates (struct iface_list *iface, char *direction)
{
    if (iface == NULL || direction == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1,"Computing rates failed because iface or direction were NULL!\n");
        return -1;
    }
    DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"=========\t%s STATS\t=========\n", direction);

    long *prev_bytes = NULL;
    int *current_offset = NULL;
    int *maximum_offset = NULL;
    double *values = NULL;
    double *max_rate = NULL;
    double *rate_current = NULL;
    double new_rate;

    char path[100];

    if (strncmp(direction, "upload", MAX_KEY_LENGTH) == 0) {
        prev_bytes = g_hash_table_lookup(iface->measure_dict, "upload_counter");
        current_offset = g_hash_table_lookup(iface->measure_dict, "upload_rate_offset");
        maximum_offset = g_hash_table_lookup(iface->measure_dict, "upload_rate_max_offset");
        values = g_hash_table_lookup(iface->measure_dict, "upload_values");
        rate_current = g_hash_table_lookup(iface->measure_dict, "upload_rate_current");
        max_rate = g_hash_table_lookup(iface->measure_dict, "upload_rate_max_recent");

        sprintf(path,"%s%s%s%s",path1,iface->if_name,path2,"tx_bytes");
    }
    else
    {
        prev_bytes = g_hash_table_lookup(iface->measure_dict, "download_counter");
        current_offset = g_hash_table_lookup(iface->measure_dict, "download_rate_offset");
        maximum_offset = g_hash_table_lookup(iface->measure_dict, "download_rate_max_offset");
        values = g_hash_table_lookup(iface->measure_dict, "download_values");
        rate_current = g_hash_table_lookup(iface->measure_dict, "download_rate_current");
        max_rate = g_hash_table_lookup(iface->measure_dict, "download_rate_max_recent");
        sprintf(path,"%s%s%s%s",path1,iface->if_name,path2,"rx_bytes");
    }

    long curr_bytes = read_stats(path);

    if (curr_bytes == 0) {
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Reading %s counters failed, returning \n", direction);
        return -1;
    }

    if(values != NULL && prev_bytes != NULL && rate_current != NULL){
        // If a counter value was found in the hash table, calculate the new rate
        // Try to base it on the actual time difference since the last callback
        // and this one

        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        double *measurement_timestamp_sec = g_hash_table_lookup(iface->measure_dict,"rate_timestamp_sec");
        double *measurement_timestamp_usec = g_hash_table_lookup(iface->measure_dict,"rate_timestamp_usec");

        if (measurement_timestamp_sec != NULL && measurement_timestamp_usec != NULL) {
            double time_diff = 0;
            if (*measurement_timestamp_sec < current_time.tv_sec) {
                time_diff = (current_time.tv_sec + current_time.tv_usec/1000000.) - (*measurement_timestamp_sec + *measurement_timestamp_usec/1000000);
            } else {
                time_diff = (current_time.tv_usec - *measurement_timestamp_usec) / 1000000.;
            }

            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Old timestamp %6.0f.%6.0f, new %6.0f.%6.0f - Time diff: %f\n",*measurement_timestamp_sec, *measurement_timestamp_usec, (double) current_time.tv_sec, (double) current_time.tv_usec, time_diff);
            new_rate = (curr_bytes - *prev_bytes)/time_diff;
        }
        else {
            // No timestamp from last callback found - use fixed value
            new_rate = (curr_bytes - *prev_bytes)/CALLBACK_DURATION;
        }
        *rate_current = new_rate;

        (*current_offset)++;
        if (*current_offset >= n_timeout) {
            *current_offset = 0;
        }

        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current offset: %d\n",*current_offset);
        values[*current_offset] = new_rate;

        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current Counter Value: %ld Bytes\n",curr_bytes);
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Previous Counter Value: %ld Bytes\n",*prev_bytes);
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Activity: %ld Bytes\n",(curr_bytes - *prev_bytes));
        *prev_bytes = curr_bytes;
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Link Usage: %f Bps\n",new_rate);

        if (new_rate > *max_rate){
            *max_rate = new_rate;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"New Max. %s rate reached: %.3fbps [at offset %d]\n", direction, *max_rate, *current_offset);
            *maximum_offset = *current_offset;
        }
        else
        {
            if (*current_offset == *maximum_offset)
            // current maximum rate timed out - need to calculate new one
            {
                *maximum_offset = rolling_maximum(values, n_timeout, *max_rate);
                *max_rate = values[*maximum_offset];
                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Old max %s rate timed out - new one %.3fbps [at offset %d]\n", direction, *max_rate, *maximum_offset);
            }
            else {
                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Old max %s rate is still valid: %.3fbps [at offset %d]\n", direction, *max_rate, *maximum_offset);
            }
        }
    }
    else {
        //initialization during the first run for a particular interface
        // cannot compute any rate yet, as no counter increase is observed
        current_offset = malloc(sizeof(int));
        maximum_offset = malloc(sizeof(int));

        long *prev_bytes = malloc(sizeof(long));
        double *values = malloc(n_timeout * sizeof(double));
        double *rate_current = malloc(sizeof(double));
        double *max_rate = malloc(sizeof(double));

        *current_offset = 0;
        *maximum_offset = 0;
        *prev_bytes = curr_bytes;
        memset(values, 0, n_timeout);
        *rate_current = 0.0;
        *max_rate = 0.0;

        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current offset: %d\n",*current_offset);
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Inserting to the dictionary\n");

        if (strncmp(direction, "upload", MAX_KEY_LENGTH) == 0) {
            g_hash_table_insert(iface->measure_dict, "upload_rate_offset", current_offset);
            g_hash_table_insert(iface->measure_dict, "upload_rate_max_offset", maximum_offset);
            g_hash_table_insert(iface->measure_dict, "upload_counter", prev_bytes);
            g_hash_table_insert(iface->measure_dict, "upload_rate_current", rate_current);
            g_hash_table_insert(iface->measure_dict, "upload_rate_max_recent", max_rate);
            g_hash_table_insert(iface->measure_dict, "upload_values", values);
        }
        else
        {
            g_hash_table_insert(iface->measure_dict, "download_rate_offset", current_offset);
            g_hash_table_insert(iface->measure_dict, "download_rate_max_offset", maximum_offset);
            g_hash_table_insert(iface->measure_dict, "download_counter", prev_bytes);
            g_hash_table_insert(iface->measure_dict, "download_rate_current", rate_current);
            g_hash_table_insert(iface->measure_dict, "download_rate_max_recent", max_rate);
            g_hash_table_insert(iface->measure_dict, "download_values", values);
        }

        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current Counter Value: %ld Bytes\n",*prev_bytes);
    }

    return 0;
}

/**
*  This function calculates the current throughput on each interface
*  For upload and download, the following metrics are stored:
*  - counter:          Current interface counter [Bytes]
*  - rate_recent:      Currently observed throughput [Bytes / second]
*                      = Difference between current and previous counter value,
*                        divided by the callback duration
*  - rate_max_recent:  Maximum of rates seen in the last n_timeout callbacks
*
*  Internally, for each interface the most recent n_timeout values are stored
*/
void compute_link_usage(void *ifc, void *lookup)
{
    struct iface_list *iface = ifc;

    if (iface == NULL){
        return;
    }

    if(strncmp(iface->if_name,"lo",2))
    {
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"\n\n==========\tINTERFACE %s\t==========\n", iface->if_name);

        // Add upload and download rates to iface->measure_dict
        compute_rates(iface, "download");
        compute_rates(iface, "upload");

        // Get timestamp and log it
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        double *measurement_timestamp_sec = g_hash_table_lookup(iface->measure_dict,"rate_timestamp_sec");
        double *measurement_timestamp_usec = g_hash_table_lookup(iface->measure_dict,"rate_timestamp_usec");

        if (measurement_timestamp_sec == NULL || measurement_timestamp_usec == NULL)
        {
            measurement_timestamp_sec = malloc(sizeof(double));
            memset(measurement_timestamp_sec, 0, sizeof(double));
            g_hash_table_insert(iface->measure_dict, "rate_timestamp_sec", measurement_timestamp_sec);
            *measurement_timestamp_sec = current_time.tv_sec;

            measurement_timestamp_usec = malloc(sizeof(double));
            memset(measurement_timestamp_usec, 0, sizeof(double));
            g_hash_table_insert(iface->measure_dict, "rate_timestamp_usec", measurement_timestamp_usec);
            *measurement_timestamp_usec = current_time.tv_usec;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Logged new timestamp %6.0f.%6.0f\n",*measurement_timestamp_sec, *measurement_timestamp_usec);
        }
        else
        {
            *measurement_timestamp_usec = current_time.tv_usec;
            *measurement_timestamp_sec = current_time.tv_sec;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Logged timestamp %6.0f.%6.0f\n",*measurement_timestamp_sec, *measurement_timestamp_usec);
        }
    }
    return;
}

void pmeasure_setup(mam_context_t *ctx)
{
    DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Setting up pmeasure \n");

    // Go through interface list. For each interface, set up the state to query additional_info
    g_slist_foreach(ctx->ifaces, &setup_additional_info, NULL);

    // Invoke callback explicitly to initialize stats
    pmeasure_callback(0, 0, ctx);
}

void pmeasure_cleanup(mam_context_t *ctx)
{
    DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Cleaning up\n");

    g_slist_foreach(ctx->ifaces, &cleanup_measure_dict_if, NULL);
    g_slist_foreach(ctx->prefixes, &cleanup_measure_dict_pf, NULL);
    // Go through interface list. For each interface, clean up the state to query additional_info
    g_slist_foreach(ctx->ifaces, &cleanup_additional_info, NULL);

    // Go through interface list. For each interface, clean up the pcap session used for passive scanning
    g_slist_foreach(ctx->ifaces, &cleanup_passive_network_load, NULL);
}

void pmeasure_callback(evutil_socket_t fd, short what, void *arg)
{
    mam_context_t *ctx = (mam_context_t *) arg;

    DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Callback invoked.\n");

    if (ctx == NULL)
        return;

    g_slist_foreach(ctx->prefixes, &compute_srtt, NULL);
    g_slist_foreach(ctx->ifaces, &get_stats, NULL);
    g_slist_foreach(ctx->ifaces, &compute_link_usage, NULL);
    g_slist_foreach(ctx->ifaces, &get_additional_info, NULL);
    DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Get packets from passive scan\n");
    g_slist_foreach(ctx->ifaces, &get_last_packet, NULL);

    if (MAM_PMEASURE_NOISY_DEBUG0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Printing summary\n");
        g_slist_foreach(ctx->prefixes, &pmeasure_print_prefix_summary, NULL);
        g_slist_foreach(ctx->ifaces, &pmeasure_print_iface_summary, NULL);
    }
    if (MAM_PMEASURE_LOGPREFIX)
    {
        g_slist_foreach(ctx->prefixes, &pmeasure_log_prefix_summary, NULL);
        g_slist_foreach(ctx->ifaces, &pmeasure_log_iface_summary, NULL);
    }

    DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Callback finished.\n\n");
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "\n\n");
}
