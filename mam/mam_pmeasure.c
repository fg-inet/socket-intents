/** \file mam_pmeasure.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <ifaddrs.h>

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
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/attr.h>

#endif /* HAVE_LIBNL */

#include <pcap.h>

#ifdef IS_LINUX
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/nl80211.h>
#include <linux/wireless.h>
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

#ifndef MAM_PMEASURE_LOSS_NOISY_DEBUG
#define MAM_PMEASURE_LOSS_NOISY_DEBUG 0
#endif

#ifndef MAM_PMEASURE_THRUPUT_DEBUG
#define MAM_PMEASURE_THRUPUT_DEBUG 0
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG_PQL
#define MAM_PMEASURE_NOISY_DEBUG_PQL 0
#endif

#define BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
#define TCPF_ALL 0xFFF

#define MAX_KEY_LENGTH 255

int compare_ip (struct sockaddr *a1, struct sockaddr *a2);
int is_addr_in_pfx (const void *a, const void *b);

void compute_srtt(void *pfx, void *data);

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

#ifdef HAVE_LIBNL
int create_nl_sock();
GList * parse_nl_msg(struct inet_diag_msg *pMsg, int rtalen, void *pfx, GList *values);
int send_nl_msg(int sock, int i);
int recv_nl_msg(int sock, void *pfx, GList **values);
void insert_errors(GHashTable *pTable, struct rtnl_link *pLink);

void get_stats(void *iface, void *data);
void get_additional_info(void *pfx, void *data);
void get_netlink_messages(void *pfx, void *data);

/* Callback functions for processing received netlink messages */
static int handle_netlink_errors(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg);
static int ack_handler(struct nl_msg *msg, void *arg);
static int finish_handler(struct nl_msg *msg, void *arg);
static int no_seq_check(struct nl_msg *msg, void *arg);
static int parse_netlink_messages(struct nl_msg *msg, void *arg);

#endif /* HAVE_LIBNL */

#ifdef IS_LINUX
/* Helpers to insert 802.11 information into the dictionary */
void insert_bss_load(struct iface_list *iface, uint8_t *data);
void insert_signal_strength(struct iface_list *iface, double data, char *key);
int parse_station_info(struct nl_msg *msg, void *arg);
void insert_rate(struct iface_list *iface, double data, char *key);
void clear_wifi_info(struct iface_list *iface);

/* Helpers to query 802.11 information */
int get_station_info(struct iface_list *iface);
#endif

/* Helpers to set up and tear down a netlink connection on an interface */
void setup_additional_info(void *ifc, void *data);
void cleanup_additional_info(void *ifc, void *data);
void cleanup_double(void *value);

void cleanup_measure_dict_pf(void *pfx, void *data);
void cleanup_measure_dict_if(void *pfx, void *data);

// The interval in which the computation of the values happens, i.e. the time between two computations (in seconds)
#ifndef CALLBACK_DURATION
static const double CALLBACK_DURATION=0.1;
#endif

#ifdef IS_LINUX
/* Helpers to passively get QBSS Load Element */
int check_bssid(const u_char *whole_packet, unsigned char *our_bssid, int header_length);
void save_qbss_load(void *ifc, const u_char *whole_packet, int position);
void get_our_bssid(void *ifc, void *data);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void get_last_packet(void *ifc, void *data);
void cleanup_passive_network_load(void *ifc, void *data);
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
#endif /* IS_LINUX */

#ifndef MAM_PMEASURE_THRUPUT_DEBUG
#define MAM_PMEASURE_THRUPUT_DEBUG 0
#endif

/** Data structure for netlink state of an interface that communicates through nl80211 to get load
*/
struct netlink_state
{
    struct nl_sock *sock;		/**< Netlink socket */
    int nl80211_id;				/**< nl80211 driver ID as destination for messages */
    int mcid;					/**< ID of multicast group we subscribed to */
    struct nl_cb *cb;			/**< Pointer to callback functions to process netlink messages */
    unsigned int dev_id;		/**< Device ID of this interface, for netlink messages */
};

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


#ifdef HAVE_LIBNL
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

    double *packet_loss = g_hash_table_lookup(prefix->measure_dict, "packet_loss_up_median");
    if (packet_loss != NULL)
        printf("\tMedian of upstream packet loss: %f \n", *packet_loss);


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

    double *signal = g_hash_table_lookup(iface->measure_dict, "signal_strength");
    if (signal != NULL)
        printf("\tSignal Strength: \t\t%.2f dBm\n", *signal);
    else if ((signal = g_hash_table_lookup(iface->measure_dict, "signal_strength_bss")) != NULL)
        printf("\tSignal Strength (BSS): \t\t%.2f dBm\n", *signal);

    double *txrate = g_hash_table_lookup(iface->measure_dict, "tx_rate");
    if (txrate != NULL)
        printf("\tTransmission Bitrate: \t\t%.2f Mbit/s\n", *txrate);

    double *rxrate = g_hash_table_lookup(iface->measure_dict, "rx_rate");
    if (rxrate != NULL)
        printf("\tReceiving Bitrate: \t\t%.2f Mbit/s\n", *rxrate);

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

    double *packet_loss = g_hash_table_lookup(prefix->measure_dict, "packet_loss_up_median");
    if (packet_loss != NULL)
        _muacc_logtofile(logfile, "%f,", *packet_loss);
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

    double *signal = g_hash_table_lookup(iface->measure_dict, "signal_strength");
    if (signal != NULL)
        _muacc_logtofile(logfile, "%.2f,", *signal);
    else
        _muacc_logtofile(logfile, "NA,");

    if ((signal = g_hash_table_lookup(iface->measure_dict, "signal_strength_bss")) != NULL)
        _muacc_logtofile(logfile, "%.2f,", *signal);
    else
        _muacc_logtofile(logfile, "NA,");

    if ((signal = g_hash_table_lookup(iface->measure_dict, "signal_strength_avg")) != NULL)
        _muacc_logtofile(logfile, "%.2f,", *signal);
    else
        _muacc_logtofile(logfile, "NA,");

    double *txrate = g_hash_table_lookup(iface->measure_dict, "tx_rate");
    if (txrate != NULL)
        _muacc_logtofile(logfile, "%.2f,", *txrate);
    else
        _muacc_logtofile(logfile, "NA,");

    double *rxrate = g_hash_table_lookup(iface->measure_dict, "rx_rate");
    if (rxrate != NULL)
        _muacc_logtofile(logfile, "%.2f,", *rxrate);
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

    #ifdef HAVE_TCP_INFO_DATA_SEGS_OUT
    GList *loss_table = g_hash_table_lookup(prefix->measure_dict, "packet_loss_up");
    GList *values3 = loss_table;
    #endif

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

                #ifdef HAVE_TCP_INFO_DATA_SEGS_OUT
                double *loss = malloc(sizeof(double));
                *loss = tcpInfo->tcpi_lost / tcpInfo->tcpi_data_segs_out;

                DLOG(MAM_PMEASURE_LOSS_NOISY_DEBUG, "Computing loss: %d / %d = %.3f\n", tcpInfo->tcpi_lost, tcpInfo->tcpi_data_segs_out, *loss);
                values3 = g_list_append(values3, loss);
                #endif

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

    #ifdef HAVE_TCP_INFO_DATA_SEGS_OUT
    if (loss_table == NULL) {
        g_hash_table_insert(prefix->measure_dict, "packet_loss_up", values3);
        DLOG(MAM_PMEASURE_LOSS_NOISY_DEBUG, "Inserted packet_loss_up\n");
    }
    #endif
    return values;
}
#endif /* HAVE_LIBNL */

/** Compute the SRTT on an prefix, except on lo
*  Insert it into the measure_dict as "srtt_median_recent"
*/
void compute_srtt(void *pfx, void *data)
{
    struct src_prefix_list *prefix = pfx;

    #ifdef HAVE_LIBNL
    // List for rtt values
    GList *values = NULL;
    #endif

    if (prefix == NULL || prefix->measure_dict == NULL)
        return;


    if (prefix->if_name != NULL && strncmp(prefix->if_name,"lo",2))
    {
        #ifdef HAVE_LIBNL
        DLOG(MAM_PMEASURE_SRTT_NOISY_DEBUG, "Computing SRTTs for a prefix of interface %s:\n", prefix->if_name);
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

        double *median_packet_loss_up = g_hash_table_lookup(prefix->measure_dict, "packet_loss_up_median");
        if (median_packet_loss_up == NULL)
        {
            median_packet_loss_up = malloc(sizeof(double));
            g_hash_table_insert(prefix->measure_dict, "packet_loss_up_median", median_packet_loss_up);
        }

        #ifdef HAVE_TCP_INFO_DATA_SEGS_OUT
        GList *packet_loss_up = g_hash_table_lookup(prefix->measure_dict, "packet_loss_up");
        if (packet_loss_up != NULL)
        {
            *median_packet_loss_up = calculate_median(&packet_loss_up);
            DLOG(MAM_PMEASURE_LOSS_NOISY_DEBUG, "Computed median packet loss: %f\n", *median_packet_loss_up);
        } else {
            DLOG(MAM_PMEASURE_LOSS_NOISY_DEBUG, "No packet loss information - setting to zero\n");
            *median_packet_loss_up = 0;
        }
        #endif

        // clean up
        g_list_free_full(values, &cleanup_double);
        g_list_free_full(vars_of_rtts, &cleanup_double);
        g_hash_table_remove(prefix->measure_dict, "vars_of_rtts");
        g_hash_table_remove(prefix->measure_dict, "packet_loss_up");
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

/** Get load of the network if some mode was specified
*  e.g., for wireless 802.11 interfaces, query signal strength
**/
void get_additional_info(void *ifc, void *data)
{
    struct iface_list *iface = ifc;

    if (ifc == NULL || iface->if_name == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Cannot get additional info for NULL network interface\n");
        return;
    }

    #ifdef HAVE_LIBNL
    // Check if this interface was marked for querying WiFi info
    if (iface->additional_info & MAM_IFACE_WIFI_STATION_INFO)
    {
        get_netlink_messages(ifc, data);
    }
    #endif
    if (iface->additional_info == MAM_IFACE_UNKNOWN_LOAD)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Network load for interface %s is unknown!\n", iface->if_name);
    }
}

#ifdef HAVE_LIBNL
/** Receive netlink messages for wireless interface, executing callbacks */
void get_netlink_messages(void *ifc, void *data)
{
    struct iface_list *iface = ifc;

    if (ifc == NULL || iface->if_name == NULL || iface->query_state == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Cannot get Netlink messages for NULL network interface\n");
        return;
    }

    // Get the netlink connection that was established for this interface
    struct wifi_state *wifi = (struct wifi_state *) iface->query_state;
    struct netlink_state *nlstate = wifi->nl_state;

    // Set netlink socket into nonblocking mode
    nl_socket_set_nonblocking(nlstate->sock);

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Trying to receive netlink messages for %s ...\n", iface->if_name);

    // Initialize counter for netlink messages
    int msgs = 0;

    // Receive netlink messages, execute callbacks on them
    int ret = nl_recvmsgs_report(nlstate->sock, nlstate->cb);

    // Check return code of receive function
    // Negative return code means error, though "-4" (Try again) means our nonblocking socket has on messages left
    if (ret < 0 && ret != -4)
    {
        // If error code: Display error message
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error when receiving netlink messages: %d (%s) \n", ret, nl_geterror( -1 * ret));
    }
    else if (ret > 0)
    {
        // If messages were received, count them towards the sum
        msgs += ret;
    }

    // If we got messages or a known error code, check for more messages
    while (ret > 0 || ret == -16 || ret == -33)
    {
        // Receive netlink messages, execute callbacks on them
        ret = nl_recvmsgs_report(nlstate->sock, nlstate->cb);

        // Check return code of receive function
        if (ret < 0 && ret != -4)
        {
            // If error code and not "-4": Display error message
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error when receiving netlink messages: %d (%s) \n", ret, nl_geterror( -1 * ret));
        }
        else if (ret > 0)
        {
            // If more messages were received, count them towards the sum
            msgs += ret;
        }
    }

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Received %d message(s) in total \n", msgs);

    // Request new station info
    get_station_info(iface);

}

/** Callback for handling netlink error messages */
static int handle_netlink_errors(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg)
{
    // Display error message, then skip to the next message
    DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Got netlink error: %d (%s)\n", nlerr->error, nl_geterror(-1 * nlerr->error));
    return NL_SKIP;
}

/** Callback for handling valid netlink messages that we received */
static int parse_netlink_messages(struct nl_msg *msg, void *arg)
{
    // Get the generic netlink message header
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));

    // Check header command
    if (hdr->cmd == NL80211_CMD_NEW_STATION)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Got new station information!\n");
        int ret = parse_station_info(msg, arg);

        if (ret == 0)
            DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Successfully parsed station info!\n");

        return NL_SKIP;
    }
    else
    {
        // Message header does not indicate that message is interesting to us
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Got a valid message with command %d, but unrelated!\n", (int) hdr->cmd);
    }

    // Skip to next message
    return NL_SKIP;
}
#endif /* HAVE_LIBNL */

#ifdef IS_LINUX
/** BSS info was found - insert it into the interface's measurement dictionary */
void insert_bss_load(struct iface_list *iface, uint8_t *data)
{
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Insert BSS load into dictionary\n");
    if (iface == NULL || data == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Load or interface was NULL - cannot insert load\n");
        return;
    }

    // Check if measurement dictionary exists for this interface
    if (iface->measure_dict == NULL)
    {
        // Initialize new measurement dictionary
        iface->measure_dict = g_hash_table_new(g_str_hash, g_str_equal);
    }

    // Lookup variables for the BSS load components from the measurement dictionary
    uint16_t *numsta = g_hash_table_lookup(iface->measure_dict, "number_of_stations"); // Number of stations
    double *channelutilization = g_hash_table_lookup(iface->measure_dict, "channel_utilization"); // Occupied airtime
    uint16_t *adcap = g_hash_table_lookup(iface->measure_dict, "available_admission_capacity"); // Capacity for QoS scheduling

    // If the variables are not initialized, initialize them
    if (numsta == NULL)
    {
        numsta = malloc(sizeof(uint16_t));
        memset(numsta, 0, sizeof(uint16_t));
        g_hash_table_insert(iface->measure_dict, "number_of_stations", numsta);
    }

    if (channelutilization == NULL)
    {
        channelutilization = malloc(sizeof(double));
        memset(channelutilization, 0, sizeof(double));
        g_hash_table_insert(iface->measure_dict, "channel_utilization", channelutilization);
    }

    if (adcap == NULL)
    {
        adcap = malloc(sizeof(uint8_t));
        memset(adcap, 0, sizeof(uint8_t));
        g_hash_table_insert(iface->measure_dict, "available_admission_capacity", adcap);
    }

    // Update the values for the BSS load components
    *numsta = data[1] << 8 | data[0]; 		// Number of associated stations
    *channelutilization = (data[2]) / 2.55; // Occupied airtime (n/255), converted to percent
    *adcap = data[4] << 8 | data[3];		// Capacity for QoS scheduling

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Number of stations: %d\n", (data[1] << 8) | data[0]);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Channel utilization: %d/255 (%.2f%%)\n", data[2], (data[2])/2.55);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Available admission capacity: %d\n", (data[4] << 8) | data[3]);
}

/** Clear wifi info when BSSID has changed */
void clear_wifi_info(struct iface_list *iface)
{
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Clearing Wifi Info from dictionary\n");
    if (iface == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Interface was NULL - cannot clear info\n");
        return;
    }

    g_hash_table_remove(iface->measure_dict, "signal_strength");
    g_hash_table_remove(iface->measure_dict, "signal_strength_avg");
    g_hash_table_remove(iface->measure_dict, "signal_strength_bss");
    g_hash_table_remove(iface->measure_dict, "rx_rate");
    g_hash_table_remove(iface->measure_dict, "tx_rate");
    g_hash_table_remove(iface->measure_dict, "number_of_stations");
    g_hash_table_remove(iface->measure_dict, "channel_utilization");
    g_hash_table_remove(iface->measure_dict, "available_admission_capacity");
}

/** Signal strength - insert it into the interface's measurement dictionary */
void insert_signal_strength(struct iface_list *iface, double data, char* key)
{
    if (iface == NULL || key == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Interface or key was NULL - cannot insert signal strength\n");
        return;
    }

    // Check if measurement dictionary exists for this interface
    if (iface->measure_dict == NULL)
    {
        // Initialize new measurement dictionary
        iface->measure_dict = g_hash_table_new(g_str_hash, g_str_equal);
    }

    // Lookup variables for the BSS load components from the measurement dictionary
    double *signal = g_hash_table_lookup(iface->measure_dict, key);

    // If the variable is not initialized, initialize it
    if (signal == NULL)
    {
        signal = malloc(sizeof(double));
        memset(signal, 0, sizeof(double));
        g_hash_table_insert(iface->measure_dict, key, signal);
    }

    // Update the values for the BSS load components
    *signal = data;

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Inserted Signal Strength %s into dictionary: %.2f \n", key, *signal);
}

/** Bitrate - insert it into the interface's measurement dictionary */
void insert_rate(struct iface_list *iface, double data, char *key)
{
    if (iface == NULL || key == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Interface or key was NULL - cannot insert bitrate\n");
        return;
    }
    // Check if measurement dictionary exists for this interface
    if (iface->measure_dict == NULL)
    {
        // Initialize new measurement dictionary
        iface->measure_dict = g_hash_table_new(g_str_hash, g_str_equal);
    }

    // Lookup variables for the BSS load components from the measurement dictionary
    double *rate = g_hash_table_lookup(iface->measure_dict, key);

    // If the variable is not initialized, initialize it
    if (rate == NULL)
    {
        rate = malloc(sizeof(double));
        memset(rate, 0, sizeof(double));
        g_hash_table_insert(iface->measure_dict, key, rate);
    }

    // Update the values for the rate
    *rate = data;

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Inserted %s bitrate into dictionary: %.2f \n", key, *rate);
}
#endif

#ifdef HAVE_LIBNL
/** Parse station information for connection on this 802.11 interface */
int parse_station_info(struct nl_msg *msg, void *arg)
{
    // Get interface for this station info
    struct iface_list *iface = arg;

    if (iface == NULL || iface->if_name == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Cannot parse load for NULL interface\n");
        return -1;
    }

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Parsing station info for interface %s\n", iface->if_name);

    // Prepare attribute index for parsing this message
    struct nlattr *attributes[NL80211_ATTR_MAX + 1];

    // Get message header
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));

    // Prepare station index for parsing
    struct nlattr *sta[NL80211_STA_INFO_MAX + 1];

    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
        [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
        [NL80211_STA_INFO_T_OFFSET] = { .type = NLA_U64 },
        [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
        [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
        [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
        [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
        [NL80211_STA_INFO_STA_FLAGS] =
            { .minlen = sizeof(struct nl80211_sta_flag_update) },
        [NL80211_STA_INFO_LOCAL_PM] = { .type = NLA_U32},
        [NL80211_STA_INFO_PEER_PM] = { .type = NLA_U32},
        [NL80211_STA_INFO_NONPEER_PM] = { .type = NLA_U32},
        [NL80211_STA_INFO_CHAIN_SIGNAL] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_CHAIN_SIGNAL_AVG] = { .type = NLA_NESTED },
    };

    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
        [NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
        [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
        [NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
        [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
        [NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
    };

    int ret = 0;

    // Parse the attributes from the message, setting the attribute index for each found attribute
    ret = nla_parse(attributes, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), NULL);

    if (ret < 0) {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to parse the message, error code: %d\n", ret);
        return -1;
    }
    if (!attributes[NL80211_ATTR_STA_INFO]) {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Station Info missing!\n");
        return 1;
    }

    ret = nla_parse_nested(sta, NL80211_STA_INFO_MAX, attributes[NL80211_ATTR_STA_INFO], stats_policy);

    if (ret < 0)
    {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return -1;
    }
    else
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Successfully parsed\n");
    }


    // Parsed message attributes - check if it contains signal strength of last packet
    if (sta[NL80211_STA_INFO_CHAIN_SIGNAL])
    {
        struct nlattr *chain_signal = sta[NL80211_STA_INFO_CHAIN_SIGNAL];
        struct nlattr *attr;
        int remaining;

        attr = nla_data(chain_signal);
        remaining = nla_len(chain_signal);

        if (nla_ok(attr, remaining)) {
            int signal = (int8_t) nla_get_u8(attr);
            insert_signal_strength(iface, (double) signal, "signal_strength");
        }

    }
    if (sta[NL80211_STA_INFO_CHAIN_SIGNAL_AVG])
    {
        struct nlattr *chain_signal = sta[NL80211_STA_INFO_CHAIN_SIGNAL_AVG];
        struct nlattr *attr;
        int remaining;

        attr = nla_data(chain_signal);
        remaining = nla_len(chain_signal);

        if (nla_ok(attr, remaining)) {
            int signal = (int8_t) nla_get_u8(attr);
            insert_signal_strength(iface, (double) signal, "signal_strength_avg");
        }


    }

    if (sta[NL80211_STA_INFO_TX_BITRATE])
    {
        // Transmitting bitrate info was found
        // Prepare attribute index for parsing the transmitting bitrate
        struct nlattr *txrate_info[NL80211_RATE_INFO_MAX + 1];

        // Parse nested rate info
        if (0 > (ret = nla_parse_nested(txrate_info, NL80211_RATE_INFO_MAX, sta[NL80211_STA_INFO_TX_BITRATE], rate_policy)))
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to parse the transmit bitrate, error code: %d\n", ret);
        }
        else
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Successfully parsed transmit rate \n");

            // Parsed receiving bitrate info
            if(txrate_info[NL80211_RATE_INFO_BITRATE32])
            {
                int txrate = nla_get_u32(txrate_info[NL80211_RATE_INFO_BITRATE32]);
                DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Transmitting bitrate32 = %d.%d Mbit/s \n", txrate/10, txrate%10);
                insert_rate(iface, (double)txrate/10, "tx_rate");
            }
            else if (txrate_info[NL80211_RATE_INFO_BITRATE])
            {
                int txrate = nla_get_u16(txrate_info[NL80211_RATE_INFO_BITRATE]);
                DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Transmitting bitrate = %d.%d Mbit/s \n", txrate/10, txrate%10);
                insert_rate(iface, (double)txrate/10, "tx_rate");
            }
        }
    }

    if (sta[NL80211_STA_INFO_RX_BITRATE])
    {
        // Receiving bitrate info was found
        // Prepare attribute index for parsing the receiving bitrate
        struct nlattr *rxrate_info[NL80211_RATE_INFO_MAX + 1];

        // Parse nested rate info
        if (0 > (ret = nla_parse_nested(rxrate_info, NL80211_RATE_INFO_MAX, sta[NL80211_STA_INFO_RX_BITRATE], rate_policy)))
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to parse the receive bitrate, error code: %d\n", ret);
        }
        else
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Successfully parsed receive rate \n");
            // Parsed receiving bitrate info
            if(rxrate_info[NL80211_RATE_INFO_BITRATE32])
            {
                int rxrate = nla_get_u32(rxrate_info[NL80211_RATE_INFO_BITRATE32]);
                DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Receiving bitrate32 = %d.%d Mbit/s \n", rxrate/10, rxrate%10);
                insert_rate(iface, (double)rxrate/10, "rx_rate");
            }
            else if (rxrate_info[NL80211_RATE_INFO_BITRATE])
            {
                int rxrate = nla_get_u16(rxrate_info[NL80211_RATE_INFO_BITRATE]);
                DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Receiving bitrate = %d.%d Mbit/s \n", rxrate/10, rxrate%10);
                insert_rate(iface, (double)rxrate/10, "rx_rate");
            }
        }
    }

    return 0;
}


/** Callback for the sequence checking errors: Ignore them, report that everything is okay
**/
static int no_seq_check(struct nl_msg *msg, void *arg)
{
    // Do not throw an error
    return NL_OK;
}

/** Callback for the receiving of the netlink ACK messages
**/
static int ack_handler(struct nl_msg *msg, void *arg)
{
    // Skip to the next message
    return NL_SKIP;
}

/** Callback for when the receiving of the netlink messages is done
**/
static int finish_handler(struct nl_msg *msg, void *arg)
{
    // Skip to the next message
    return NL_SKIP;
}

int get_station_info(struct iface_list *iface)
{
    struct wifi_state *wifi = iface->query_state;
    if (wifi == NULL || wifi->nl_state == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Wifi state not initialized - Cannot get station info! \n");
        return -1;
    }

    // Check if we know a BSSID yet
    if (wifi->bssid[0] == 0 && wifi->bssid[1] == 0 && wifi->bssid[2] == 0 && wifi->bssid[3] == 0 && wifi->bssid[4] == 0 && wifi->bssid[5] == 0)
    {
        // We don't - get it first
        get_our_bssid((void *) iface, NULL);
    }

    // Allocate netlink message
    struct nl_msg *msg = nlmsg_alloc();

    // Check if allocation failed
    if (!msg)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to allocate netlink message\n");
        return -1;
    }

    // Set up a generic netlink message that gets 802.11 station information
    genlmsg_put(msg, 0, 0, wifi->nl_state->nl80211_id, 0, 0, NL80211_CMD_GET_STATION, 0);

    nla_put(msg, NL80211_ATTR_MAC, 6, wifi->bssid);

    // Add message attribute: ID of the current interface
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, wifi->nl_state->dev_id);

    // Send the message
    nl_send_auto_complete(wifi->nl_state->sock, msg);

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Requested station information on BSSID %02x:%02x:%02x:%02x:%02x:%02x\n", wifi->bssid[0], wifi->bssid[1], wifi->bssid[2], wifi->bssid[3], wifi->bssid[4], wifi->bssid[5]);

    // Free the message
    nlmsg_free(msg);

    return 0;
}
#endif

/** For each interface, set up state to query additional_info
*  e.g. prepare netlink sockets for querying BSS load on 802.11 interfaces
*/
void setup_additional_info(void *ifc, void *data)
{
    struct iface_list *iface = ifc;

    if (ifc == NULL || iface->if_name == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Cannot setup load for NULL network interface\n");
        return;
    }
    #ifdef HAVE_LIBNL
    // Check if we are querying additional information for this interface
    if (iface->additional_info & MAM_IFACE_WIFI_STATION_INFO)
    {
        // Set up netlink socket and callbacks
        struct wifi_state *wifi = iface->query_state;

        if (wifi == NULL)
        {
            wifi = malloc(sizeof(struct wifi_state));
            if (wifi == NULL) {
                DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to allocate wifi state\n");
                iface->additional_info &= ~(MAM_IFACE_WIFI_STATION_INFO);
                return;
            }
            memset(wifi, 0, sizeof(struct wifi_state));
            iface->query_state = wifi;
        }

        // Allocate memory for netlink socket and callbacks
        struct netlink_state *nlstate = malloc(sizeof(struct netlink_state));
        nlstate->sock = nl_socket_alloc();

        if (nlstate == NULL || !nlstate->sock)
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to allocate netlink state or socket\n");
            iface->additional_info &= ~(MAM_IFACE_WIFI_STATION_INFO);
            return;
        }

        // Set the socket to nonblocking
        nl_socket_set_nonblocking(nlstate->sock);

        // Set socket buffer size to one page
        nl_socket_set_buffer_size(nlstate->sock, BUFFER_SIZE, BUFFER_SIZE);

        // Connect the socket to the generic netlink interface
        if (genl_connect(nlstate->sock) < 0)
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to connect netlink socket\n");
            nl_socket_free(nlstate->sock);
            free(nlstate);
            free(wifi);
            iface->query_state = NULL;
            iface->additional_info &= ~(MAM_IFACE_WIFI_STATION_INFO);
            return;
        }

        // Resolve the nl80211 family name to a numeric identifier
        nlstate->nl80211_id = genl_ctrl_resolve(nlstate->sock, "nl80211");
        if (nlstate->nl80211_id < 0)
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "nl80211 interface not found\n");
            nl_socket_free(nlstate->sock);
            free(nlstate);
            free(wifi);
            iface->query_state = NULL;
            iface->additional_info &= ~(MAM_IFACE_WIFI_STATION_INFO);
            return;
        }

        // Resolve multicast group ID for scan results and add our socket to it
        nlstate->mcid = genl_ctrl_resolve_grp(nlstate->sock, "nl80211", "scan");
        nl_socket_add_membership(nlstate->sock, nlstate->mcid);

        // Allocate a netlink callback set and initialize it to the default set
        nlstate->cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!nlstate->cb)
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Failed to allocate netlink callback\n");
            nl_socket_free(nlstate->sock);
            free(nlstate);
            free(wifi);
            iface->query_state = NULL;
            iface->additional_info &= ~(MAM_IFACE_WIFI_STATION_INFO);
            return;
        }

        // Set the callback for all valid messages to a function that parses them
        nl_cb_set(nlstate->cb, NL_CB_VALID, NL_CB_CUSTOM, parse_netlink_messages, iface);

        // Set the error message handler to a function that prints the error
        nl_cb_err(nlstate->cb, NL_CB_CUSTOM, handle_netlink_errors, NULL);

        // Set a callback for the message when we are finished
        nl_cb_set(nlstate->cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);

        // Set the callback for ACKs
        nl_cb_set(nlstate->cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, NULL);

        // Disable sequence checking for multicast messages
        nl_cb_set(nlstate->cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);

        // Resolve device ID (needed for messages)
        nlstate->dev_id = if_nametoindex(iface->if_name);

        // Attach the netlink state to the interface data structure
        iface->query_state = wifi;
        memset(wifi->bssid, 0, 6);
        wifi->nl_state = nlstate;

        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Set up additional_info state for interface %s\n", iface->if_name);

        if (iface->additional_info & MAM_IFACE_WIFI_STATION_INFO) {
            // Get 802.11 station information on this interface
            if (0 == get_station_info(iface))
            {
                DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Requested station info on %s\n", iface->if_name);
            }
        }
    }
    #endif
}

/** When shutting down pmeasure, clean up the additional_info querying state for each interface
*/
void cleanup_additional_info(void *ifc, void *data)
{
    struct iface_list *iface = ifc;

    if (ifc == NULL || iface->if_name == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Cannot cleanup additional_info state for NULL network interface\n");
        return;
    }

    #ifdef HAVE_LIBNL
    // Check if 802.11 BSS Load attribute was set
    if (iface->additional_info & MAM_IFACE_WIFI_STATION_INFO)
    {
        // This is a 802.11 interface for which we set up netlink state - clean it up
        struct wifi_state *wifi = (struct wifi_state *) iface->query_state;
        if (wifi != NULL) {
            struct netlink_state *nlstate = wifi->nl_state;
            if (nlstate != NULL)
            {
                // Free the socket, message and callbacks
                nl_cb_put(nlstate->cb);
                nl_socket_drop_membership(nlstate->sock, nlstate->mcid);
                nl_socket_free(nlstate->sock);
                free(nlstate);
                wifi->nl_state = NULL;
            }
        }
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Cleaned up additional_info state for interface %s\n", iface->if_name);
    }
    #endif
}

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

    double *signal = g_hash_table_lookup(iface->measure_dict, "signal_strength");
    if (signal != NULL)
        free(signal);
    signal = g_hash_table_lookup(iface->measure_dict, "signal_strength_bss");
    if (signal != NULL)
        free(signal);
    signal = g_hash_table_lookup(iface->measure_dict, "signal_strength_avg");
    if (signal != NULL)
        free(signal);

    double *txrate = g_hash_table_lookup(iface->measure_dict, "tx_rate");
    if (txrate != NULL)
        free(txrate);

    double *rxrate = g_hash_table_lookup(iface->measure_dict, "rx_rate");
    if (rxrate != NULL)
        free(rxrate);

    uint16_t *numsta = g_hash_table_lookup(iface->measure_dict, "number_of_stations");
    if (numsta != NULL)
        free(numsta);

    double *channelutilization = g_hash_table_lookup(iface->measure_dict, "channel_utilization");
    if (channelutilization != NULL)
        free(channelutilization);

    uint16_t *adcap = g_hash_table_lookup(iface->measure_dict, "available_admission_capacity");
    if (adcap != NULL)
        free(adcap);
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
    #ifdef IS_LINUX
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

    #endif
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

/*BEGIN OF THE PASSIVE BSS LOAD ELEMENT GETTER PART*/

#ifdef HAVE_LIBNL
//Checks if we got a beacon with the BSSID of AP we are associated with
int check_bssid(const u_char *whole_packet, unsigned char *our_bssid, int header_length)
{
    // Offset of the bssid in whole beacon frame
    int offset_begin = header_length + 16; // 16 bytes is the offset of BSSID in beacon frame field.
    int offset_end = header_length + 16 + 6;

    // Save the received bssid here
    unsigned char got_bssid[6];
    bzero(got_bssid,6);

    // Start at the beginning of the bssid and copy it bytewise
    int i = offset_begin;
    while (i < offset_end) {
        got_bssid[i - offset_begin] = whole_packet[i];
        i++;
    }

    DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Got beacon frame with BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", got_bssid[0], got_bssid[1], got_bssid[2], got_bssid[3], got_bssid[4], got_bssid[5]);
    // Chceck if that beacon was from AP we are associated with
    i = 0;
    while (i < 6) {
        if (got_bssid[i] != our_bssid[i]) {
            DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "This beacon frame was not from our AP!\n");
            return -1;
        }
        i++;
    }
    DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "We received a beacon frame from our AP!\n");
    return 0;
}

// Saves the necessary BSS Load Values
void save_qbss_load(void *ifc, const u_char *whole_packet, int position)
{
    struct iface_list *iface = ifc;
    uint8_t data[5];
    unsigned int i = 0;
    while (i < 5) {
        data[i] = whole_packet[position + 2 + i];
        i++;
    }
    // DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Station count: \t \t %d\n", whole_packet[position + 3] << 8 | whole_packet[position + 2]);
    // DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Channel utilization: \t \t %d\n", whole_packet[position + 4]);
    // DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Admission Capabilities: \t \t %d\n", whole_packet[position + 6] << 8 | whole_packet[position + 5]);
    insert_bss_load(iface, data);
}

// On pcap_dispatch this function will be executed for each beacon frame obtained
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct iface_list *iface = (struct iface_list*)param;
    struct wifi_state *wifi = iface->query_state;
    int length = header->caplen;
    int header_len = pkt_data[2];
    int i = header_len + 36;
    if (check_bssid(pkt_data, wifi->bssid, header_len) == -1) return;
    DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Handle beacon frame from our AP on interface: %s\n", iface->if_name);
    while (i < length) {
        switch (pkt_data[i]) {
            case QBSS_LOAD_ELEMENT_TAG:{
                DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "This beacon contained the QBSS Load! Saving it for later use.\n");
                save_qbss_load(iface, pkt_data, i);
                i += pkt_data[i+1] + 2;
                return;
            }
            default: i += pkt_data[i+1] + 2; break;

        }
    }
    DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Unfortunately this beacon frame had no QBSS Load Element in it :(\n");
}

//Checks which AP we are currently associated with
void get_our_bssid(void *ifc, void *data)
{
    struct iface_list *iface = ifc;
    struct wifi_state *wifi = iface->query_state;
    int sock = -1;
    struct iwreq iw_data;
    memset(&iw_data, 0 , sizeof(iw_data));
    // Write interface name to query data structure
    strncpy(iw_data.ifr_name, iface->if_name, IFNAMSIZ);

    // Open socket for querying the wireless extension protocol
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Cannot open socket - no way to determine the current BSSID\n");
        return;
    }

    // Do ioctl request for the wireless extension protocol of this interface
    int ret = -1;
    if ((ret = ioctl(sock, SIOCGIWAP, &iw_data)) != 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "IOCTL on interface %s FAILED! Couldn't get current BSSID\n", iface->if_name);
    }
    else
    {
        unsigned char our_bssid[6];
        unsigned int i = 0;
        while (i < 6) {
            our_bssid[i] = (u_char)iw_data.u.ap_addr.sa_data[i];
            i++;
        }
        if (wifi->bssid[0] != our_bssid[0] || wifi->bssid[1] != our_bssid[1] || wifi->bssid[2] != our_bssid[2] || wifi->bssid[3] != our_bssid[3] || wifi->bssid[4] != our_bssid[4] || wifi->bssid[5] != our_bssid[5]) {
            DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "BSSID changed! Clearing wifi info! \n");
            clear_wifi_info(iface);
        }
        memcpy(wifi->bssid, our_bssid, 6);
        DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Our BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", our_bssid[0], our_bssid[1], our_bssid[2], our_bssid[3], our_bssid[4], our_bssid[5]);
    }
    close(sock);
}

void get_last_packet(void *ifc, void *data)
{
    struct iface_list *iface = ifc;
    struct wifi_state *wifi = iface->query_state;
    if ((iface->additional_info & MAM_IFACE_QUERY_BSS_LOAD) && wifi->sniffer != NULL) { // Check if we have pcap capture
        DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Begin dispatch to get passive network load for interface: %s\n", iface->if_name);
        get_our_bssid(ifc, data);
        if(pcap_dispatch(wifi->sniffer, -1, packet_handler, (u_char*) iface) < 0) {
            DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Error on dispatch - stop monitoring BSS Load\n");
            pcap_close(wifi->sniffer);
            wifi->sniffer = NULL;
            iface->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
        }
    } else {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Load cannot be queried on interface: %s. Error: \n", iface->if_name);
        if (!(iface->additional_info & MAM_IFACE_QUERY_BSS_LOAD)) {
            DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Load query is not enabled for this interface.\n");
        } else if (wifi->sniffer == NULL) {
            DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "No load queried on %s - Pcap capturing device failed.\n", iface->if_name);
        } else {
            DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "No load queried on %s - Other error.\n", iface->if_name);
        }

    }
}

void cleanup_passive_network_load(void *ifc, void *data)
{
    struct iface_list *iface = ifc;

    if (ifc == NULL || iface->if_name == NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Cannot cleanup passive network load state for NULL network interface\n");
        return;
    }

    // Check if 802.11 BSS Load attribute was set
    if (iface->additional_info & MAM_IFACE_QUERY_BSS_LOAD)
    {
        // If something needs to be cleaned up, it can be added here.
        DLOG(MAM_PMEASURE_NOISY_DEBUG_PQL, "Cleaned up passive network load state for interface %s\n", iface->if_name);
    }
}
#endif

/*END OF THE PASSIVE BSS LOAD ELEMENT GETTER PART*/

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

    #ifdef HAVE_LIBNL
    // Go through interface list. For each interface, clean up the pcap session used for passive scanning
    g_slist_foreach(ctx->ifaces, &cleanup_passive_network_load, NULL);
    #endif
}

void pmeasure_callback(evutil_socket_t fd, short what, void *arg)
{
    mam_context_t *ctx = (mam_context_t *) arg;

    DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Callback invoked.\n");

    if (ctx == NULL)
        return;

    g_slist_foreach(ctx->prefixes, &compute_srtt, NULL);
    g_slist_foreach(ctx->ifaces, &compute_link_usage, NULL);
    #ifdef HAVE_LIBNL
    g_slist_foreach(ctx->ifaces, &get_stats, NULL);
    g_slist_foreach(ctx->ifaces, &get_additional_info, NULL);
    DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Get packets from passive scan\n");
    g_slist_foreach(ctx->ifaces, &get_last_packet, NULL);
    #endif

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
