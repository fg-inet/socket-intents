/** \file mam_pmeasure.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
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

#include <glib.h>
#include "mam.h"
#include "mam_pmeasure.h"

#include "clib/muacc_util.h"
#include "clib/dlog.h"

#ifdef HAVE_LIBNL
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/idiag/idiagnl.h>
#include <netlink/idiag/vegasinfo.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG0
#define MAM_PMEASURE_NOISY_DEBUG0 0
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG1
#define MAM_PMEASURE_NOISY_DEBUG1 0
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG2
#define MAM_PMEASURE_NOISY_DEBUG2 0
#endif

void compute_srtt(void *pfx, void *data);

int compare_ip (struct sockaddr *a1, struct sockaddr *a2);
int is_addr_in_pfx (const void *a, const void *b);

void compute_median(GHashTable *dict, GList *values);
void compute_mean(GHashTable *dict, GList *values);
void compute_minimum(GHashTable *dict, GList *values);

#ifdef HAVE_LIBNL

#define BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
#define TCPF_ALL 0xFFF

void get_stats(void *pfx, void *data);
int create_nl_sock();
GList * parse_nl_msg(struct inet_diag_msg *pMsg, int rtalen, void *pfx, GList *values);
int send_nl_msg(int sock, int i);
int recv_nl_msg(int sock, void *pfx, GList **values);
void insert_errors(GHashTable *pTable, struct rtnl_link *pLink);
#endif

// The interval in which the computation of the values happens, i.e. the time between two computations (in seconds)
#ifndef CALLBACK_DURATION
static const double CALLBACK_DURATION=10.0;
#endif

// The number of samples that are collected before a maximum rate is computed
#ifndef MAX_SAMPLE
static const int MAX_SAMPLE=30;
#endif

// The smoothing factor for the rates (i.e. the weight of the new value)
#ifndef SMOOTH_FACTOR
static const double SMOOTH_FACTOR = 0.125;
#endif

// The smoothing factor for the maximum rates (i.e. the weight of the new value)
#ifndef SMOOTH_FACTOR_M
static const double SMOOTH_FACTOR_M = 0.125;
#endif

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

void compute_link_usage(void *pfx, void *lookup);

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

/** Compute the mean SRTT from the currently valid srtts
 *  Insert it into the measure_dict as "srtt_mean"
 */
void compute_mean(GHashTable *dict, GList *values)
{

    double *meanvalue;
    double old_rtt;

    int n = g_list_length(values);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List for interface has length %d\n", n);

    meanvalue = g_hash_table_lookup(dict, "srtt_mean");

    if (meanvalue == NULL)
    {
        meanvalue = malloc(sizeof(double));
        memset(meanvalue, 0, sizeof(double));
        g_hash_table_insert(dict, "srtt_mean", meanvalue);
    }

    if (n == 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List is empty, there is no mean value.\n");
        *meanvalue = 0;
        return;
    }


    old_rtt = *meanvalue;

    for (int i = 0; i < n; i++)
    {
        *meanvalue += *(double *) values->data;
        values = values->next;
    }

    *meanvalue = *meanvalue / n;
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List of length %d has mean value %f \n", n, *meanvalue);

    // calculate SRTT in accord with the formula
    // SRTT = (alpha * SRTT) + ((1-alpha) * RTT)
    // see RFC793
    *meanvalue = (alpha * *meanvalue) + ((1-alpha) * old_rtt);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List of length %d has smoothed mean value %f \n", n, *meanvalue);
}

/** Compute the median SRTT from a table of individual flows with their SRTTs
 *  Insert it into the measure_dict as "srtt_median"
 */
void compute_median(GHashTable *dict, GList *values)
{
    double *medianvalue;

    int n;

    n = g_list_length(values);

    medianvalue = g_hash_table_lookup(dict, "srtt_median");

    if (medianvalue == NULL)
    {
        medianvalue = malloc(sizeof(double));
        memset(medianvalue, 0, sizeof(double));
        g_hash_table_insert(dict, "srtt_median", medianvalue);
    }

    if (n == 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List is empty, there is no median value.\n");
        *medianvalue = 0;
        return;
    }
    else if (n % 2)
    {
        // odd number of elements
        *medianvalue = *(double *) g_list_nth(values, (n/2))->data;
    }
    else
    {
        // even number of elements
        double val1 = *(double *) g_list_nth(values, (n/2)-1)->data;
        double val2 = *(double *) g_list_nth(values, (n/2))->data;
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "(intermediate value between %d. element %f and %d. element %f)\n",(n-1)/2, val1, (n+1)/2, val2);
        *medianvalue = (val1 + val2) / 2;
    }

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List of length %d has median value %f \n", n, *medianvalue);
}

void compute_minimum(GHashTable *dict, GList *values)
{
    double *minimum;

    int n;

    n = g_list_length(values);

    minimum = g_hash_table_lookup(dict, "srtt_minimum");

    if (minimum == NULL)
    {
        minimum = malloc(sizeof(double));
        memset(minimum, 0, sizeof(double));
        g_hash_table_insert(dict, "srtt_minimum", minimum);
    }

    if (n == 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List is empty, there is no minimum value.\n");
        *minimum = 0;
        return;
    }
    else
    {
        *minimum = *(double *) g_list_first(values)->data;
    }

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List of length %d has minimum value %f \n", n, *minimum);
}

#ifdef HAVE_LIBNL
void insert_errors(GHashTable *dict, struct rtnl_link *link)
{
    uint64_t *tx_errors;
    uint64_t *rx_errors;

    tx_errors = g_hash_table_lookup(dict, "tx_errors");
    rx_errors = g_hash_table_lookup(dict, "rx_error");

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

#ifdef IS_LINUX
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
    }
    fscanf(fp,"%ld",&curr_counter);
    fclose(fp);
    return curr_counter;
}
#endif

/**
 *This function computes the link usage for each interface. Many key values are stored in the dictonary of each interface.
 For the upload and download activity on the interface:
 The previous counter value with the key "upload_counter" and "download_counter"
 The data rate in the 10 second duration with the key "upload_rate" and "download_rate"
 The smoothed data rate which is a function of data rate(prev line) and previously calculated smoothed data rate with keys "upload_srate"
 and "download_srate"
 The function also observes the maximum data rate reached on each interface in a partical sample period(currently 5 min) They are stored
 with the keys "upload_max_rate" and "download_max_rate"
 Finally, The smoothed maximal data rate is calulated(from periodic maximal rates and previous smoothed maximal data rate)
 */
void compute_link_usage(void *pfx, void *lookup)
{
	#ifdef IS_LINUX
    struct src_prefix_list *prefix = pfx;
    char path[100];

    long curr_bytes;
    double curr_rate;
    double curr_srate;
    double curr_MSrate;
    long *prev_bytes;
    double *prev_rate;
    double *prev_srate;
    double *prev_Mrate;
    double *prev_MSrate;

    int *prev_sample;

    if (prefix == NULL){
        return;
    }

    if(strcmp(prefix->if_name,"lo"))
    {
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"\n\n==========\tINTERFACE\t==========\n");

        /******************************************************************************
         ****************    Upload Activity
         ******************************************************************************/
        //creating path for tx_bytes starts
        sprintf(path,"%s%s%s%s",path1,prefix->if_name,path2,"tx_bytes");
        //creating path for tx_bytes ends
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Interface: %s\n",prefix->if_name);
        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"=========\tUPLOAD STATS\t=========\n");

        //reading last counter from dictionary starts
        prev_bytes = g_hash_table_lookup(prefix->measure_dict, "upload_counter");
        prev_rate = g_hash_table_lookup(prefix->measure_dict, "upload_rate");
        prev_srate = g_hash_table_lookup(prefix->measure_dict, "upload_srate");
        prev_Mrate = g_hash_table_lookup(prefix->measure_dict,"upload_max_rate");
        prev_sample = g_hash_table_lookup(prefix->measure_dict,"sample");
        //reading last counter from dictionary ends

        //reading interface counter starts
        curr_bytes = read_stats(path);
        //reading interface counter ends
        if(prev_bytes){
            (*prev_sample)++;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Sample Number: %d\n",*prev_sample);
            curr_rate = (curr_bytes - *prev_bytes)/CALLBACK_DURATION;

            //calculating smooth upload rate starts
            curr_srate = SMOOTH_FACTOR*(curr_rate) + (1-SMOOTH_FACTOR)*(*prev_srate);
            //calculating smooth upload rate ends

            *prev_rate = curr_rate;
            *prev_srate = curr_srate;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Updating the dictionary\n");
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current Counter Value: %ld Bytes\n",curr_bytes);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Previous Counter Value: %ld Bytes\n",*prev_bytes);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Activity: %ld Bytes\n",(curr_bytes - *prev_bytes));
            *prev_bytes = curr_bytes;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Upload Link Usage: %f Bps\n",*prev_rate);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Smoothed Upload Link Usage: %f Bps\n",*prev_srate);

            //Periodic Maximal Data rate determination starts

            //Check if a new maximum data rate has been achieved in the sample period.
            if (curr_rate > *prev_Mrate){
                *prev_Mrate = curr_rate;
                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"New Max. upload rate reached: %.3fbps\n",*prev_Mrate);
            }

            //Check if the end of the sample period has been reached.
            if (*prev_sample == MAX_SAMPLE){

                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"End of Sample duration\n");

                //fetch the previous maximal smoothed rate (0.0 for the first sample period)
                prev_MSrate = g_hash_table_lookup(prefix->measure_dict,"upload_max_srate");
                //determine the newest smoothed maximam data rate.
                curr_MSrate = SMOOTH_FACTOR_M*(*prev_Mrate) + (1-SMOOTH_FACTOR_M)*(*prev_MSrate);
                *prev_MSrate = curr_MSrate;

                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"The Max. upload rate of this sample period: %.3fbps\n",*prev_Mrate);
                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"The new smooth Max. upload rate: %.3fbps\n",*prev_MSrate);
                *prev_Mrate = curr_rate;
            }
            //periodic maximal ends
        }
        else {
            //initialization during the first run for a particular interface
            int *sample = malloc(sizeof(int));

            long *t_bytes = malloc(sizeof(long));
            double *upload_rate = malloc(sizeof(double));
            double *s_up_rate = malloc(sizeof(double));
            double *period_up_rate_max = malloc(sizeof(double));
            double *period_up_rate_smooth = malloc(sizeof(double));

            *sample = 0;
            *t_bytes = curr_bytes;
            *upload_rate = 0.0;
            *s_up_rate = 0.0;
            *period_up_rate_max = 0.0;
            *period_up_rate_smooth = 0.0;

            prev_sample = sample;

            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Sample Number: %d\n",*sample);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Inserting to the dictionary\n");
            g_hash_table_insert(prefix->measure_dict, "sample",sample);
            g_hash_table_insert(prefix->measure_dict, "upload_counter",t_bytes);
            g_hash_table_insert(prefix->measure_dict, "upload_rate",upload_rate);
            g_hash_table_insert(prefix->measure_dict, "upload_max_rate",period_up_rate_max);
            g_hash_table_insert(prefix->measure_dict, "upload_srate",s_up_rate);
            g_hash_table_insert(prefix->measure_dict, "upload_max_srate",period_up_rate_smooth);

            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current Counter Value: %ld Bytes\n",*t_bytes);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Upload Link Usage: %f Bps\n",*upload_rate);
        }

        prev_bytes = NULL;
        prev_rate = NULL;
        prev_srate = NULL;
        prev_Mrate = NULL;

        /******************************************************************************
         ****************    Download Activity
         ******************************************************************************/
        //creating path for rx_bytes starts
        sprintf(path,"%s%s%s%s",path1,prefix->if_name,path2,"rx_bytes");
        //creating path for rx_bytes ends

        DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"=========\tDOWNLOAD STATS\t=========\n");
        //reading last counter from dictionary starts
        prev_bytes = g_hash_table_lookup(prefix->measure_dict, "download_counter");
        prev_rate = g_hash_table_lookup(prefix->measure_dict, "download_rate");
        prev_srate = g_hash_table_lookup(prefix->measure_dict, "download_srate");
        prev_Mrate = g_hash_table_lookup(prefix->measure_dict,"download_max_rate");
        //reading last counter from dictionary ends

        //reading interface counter starts
        curr_bytes = read_stats(path);
        //reading interface counter ends
        if(prev_bytes){
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Sample Number: %d\n",*prev_sample);
            curr_rate = (curr_bytes - *prev_bytes)/CALLBACK_DURATION;

            //calculating smooth download rate starts
            curr_srate = SMOOTH_FACTOR*(curr_rate) + (1-SMOOTH_FACTOR)*(*prev_srate);
            //calculating smooth download rate ends

            *prev_rate = curr_rate;
            *prev_srate = curr_srate;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Updating the dictionary\n");
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current Counter Value: %ld Bytes\n",curr_bytes);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Previous Counter Value: %ld Bytes\n",*prev_bytes);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Activity: %ld Bytes\n",(curr_bytes - *prev_bytes));
            *prev_bytes = curr_bytes;
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Download Link Usage: %f Bps\n",*prev_rate);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Smoothed Download Link Usage: %f Bps\n",*prev_srate);

            //Periodic Maximal Data rate determination starts

            //Check if a new maximum data rate has been achieved in the sample period.
            if (curr_rate > *prev_Mrate){
                *prev_Mrate = curr_rate;
                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"New Max. download rate reached: %.3fbps\n",*prev_Mrate);
            }

            //Check if the end of the sample period has been reached.
            if (*prev_sample == MAX_SAMPLE){

                *prev_sample = 0;
                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"End of Sample duration\n");
                //fetch the previous maximal smoothed rate (0.0 for the first sample period)
                prev_MSrate = g_hash_table_lookup(prefix->measure_dict,"download_max_srate");
                //determine the newest smoothed maximam data rate.
                curr_MSrate = SMOOTH_FACTOR_M*(*prev_Mrate) + (1-SMOOTH_FACTOR_M)*(*prev_MSrate);
                *prev_MSrate = curr_MSrate;

                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"The Max. download rate of this sample period: %.3fbps\n",*prev_Mrate);
                DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"The new smooth Max. download rate: %.3fbps\n",*prev_MSrate);
                *prev_Mrate = curr_rate;
            }
            //periodic maximal ends
        }
        else {
            //initialization during the first run for a particular interface
            long *r_bytes = malloc(sizeof(long));
            double *download_rate = malloc(sizeof(double));
            double *s_download_rate = malloc(sizeof(double));
            double *period_down_rate_max = malloc(sizeof(double));
            double *period_down_rate_smooth = malloc(sizeof(double));

            *r_bytes = curr_bytes;
            *download_rate = 0.0;
            *s_download_rate = 0.0;
            *period_down_rate_max = 0.0;
            *period_down_rate_smooth = 0.0;

            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Sample Number: %d\n",*prev_sample);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Inserting to the dictionary\n");
            g_hash_table_insert(prefix->measure_dict, "download_counter",r_bytes);
            g_hash_table_insert(prefix->measure_dict, "download_rate",download_rate);
            g_hash_table_insert(prefix->measure_dict, "download_max_rate",period_down_rate_max);
            g_hash_table_insert(prefix->measure_dict, "download_srate",s_download_rate);
            g_hash_table_insert(prefix->measure_dict, "download_max_srate",period_down_rate_smooth);

            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Current Counter Value: %ld Bytes\n",*r_bytes);
            DLOG(MAM_PMEASURE_THRUPUT_DEBUG,"Upload Link Usage: %f Bps\n",*download_rate);
        }

    }
	#endif
return;
}


/** Print the available measurement data for each prefix */
void pmeasure_print_prefix_summary(void *pfx, void *data)
{
	struct src_prefix_list *prefix = pfx;

	if (prefix == NULL || prefix->measure_dict == NULL)
		return;
    printf("Summary for prefix on interface %s, Family: %s\n", prefix->if_name, prefix->family == AF_INET?"IPv4":"IPv6");
	double *meanvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_mean");
	if (meanvalue != NULL)
		printf("\tMean SRTT: %f ms\n", *meanvalue);

	double *medianvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_median");
	if (medianvalue != NULL)
		printf("\tMedian SRTT: %f ms\n", *medianvalue);


    uint64_t  *rx_errors = g_hash_table_lookup(prefix->measure_dict, "rx_errors");
    if (rx_errors != NULL)
        printf("\tRX Errors: %" PRIu64 " \n", *rx_errors);

    uint64_t *tx_errors = g_hash_table_lookup(prefix->measure_dict, "tx_errors");
    if (medianvalue != NULL)
        printf("\tTX Errors: %" PRIu64 " \n", *tx_errors);

	printf("\n");
}

void pmeasure_print_iface_summary(void *ifc, void *data)
{
	struct iface_list *iface = ifc;

	if (iface == NULL || iface->measure_dict == NULL)
		return;

    printf("Summary for interface %s\n", iface->if_name);

    uint16_t *numsta = g_hash_table_lookup(iface->measure_dict, "number_of_stations");
	if (numsta != NULL)
        printf("\tNumber of stations: %" PRIu16 " \n", *numsta);

    uint8_t *chanutil = g_hash_table_lookup(iface->measure_dict, "channel_utilization_/255");
	if (chanutil != NULL)
        printf("\tChannel utilization: %" PRIu8 "/255 (%.2f%%)  \n", *chanutil, (*chanutil/255.0));

    uint16_t *adcap = g_hash_table_lookup(iface->measure_dict, "available_admission_capacity");
	if (adcap != NULL)
        printf("\tAvailable admission capacity: %" PRIu16 " \n", *adcap);

	printf("\n");
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
    // in the states TCP_SYN_RECV, TCP_TIME_WAIT and TCP_CLOSE
    request.idiag_states = TCPF_ALL & ~((1<<TCP_SYN_RECV) | (1<<TCP_TIME_WAIT) | (1<<TCP_CLOSE));

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

    while (1)
    {
        // receive the message
        numbytes = recv(sock, msg_buf, sizeof(msg_buf), 0);
        nlh = (struct nlmsghdr*) msg_buf;

        while (NLMSG_OK(nlh, numbytes))
        {
            // received last message
            if (nlh->nlmsg_type == NLMSG_DONE)
                return EXIT_SUCCESS;

            // Error in message
            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                DLOG(MAM_PMEASURE_NOISY_DEBUG1,"Error in netlink Message");
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
                return values; break;
        }
        case(AF_INET):
        {
            if ( (is_addr_in_pfx(pfx, &msg_addr_v4) != 0))
                return values; break;
        }
        default: return values;
    }
    //DLOG(MAM_PMEASURE_NOISY_DEBUG1,"%s is in the Prefixlist\n", address);

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
                // append it to the list of values
                double rtt = tcpInfo->tcpi_rtt/1000;
                //DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Adding %f to values\n", rtt);
                values = g_list_append(values, &rtt);
                //DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Values has now length %d\n", g_list_length(values));
            }
            //Get next attributes
            attr = RTA_NEXT(attr, rtalen);
        }
        }
    return values;
}
#endif

/** Compute the SRTT on an interface
 *  Insert it into the measure_dict as "srtt_median"
 */
void compute_srtt(void *pfx, void *data)
{
	struct src_prefix_list *prefix = pfx;

    // List for rtt values
    GList *values = NULL;

	if (prefix == NULL || prefix->measure_dict == NULL)
		return;


	if (prefix->if_name != NULL)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Computing median SRTTs for a prefix of interface %s:\n", prefix->if_name);

		#ifdef HAVE_LIBNL
        // create the socket
        int sock_ip4 = create_nl_sock();
        int sock_ip6 = create_nl_sock();

        if (sock_ip4 == EXIT_FAILURE || sock_ip6 == EXIT_FAILURE)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Socket creation failed");

        // Create and send netlink messages
        // we have to send two different requests, the first time
        // with the IPv4 Flag and the other time with the IPv6 flag
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Sending IPv4 Request\n");
        if (send_nl_msg(sock_ip4, AF_INET) == -1)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, " Error sending Netlink Request");

        // receive messages
        if (recv_nl_msg(sock_ip4, prefix, &values) != 0)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error receiving Netlink Messages")

        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Sending IPv6 Request\n");
        if (send_nl_msg(sock_ip6, AF_INET6) == -1)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, " Error sending Netlink Request");

        if (recv_nl_msg(sock_ip6, prefix, &values) != 0)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error receiving Netlink Messages");

        // compute mean, median and minimum out of the
        // rtt values and write it into the dict
        compute_mean(prefix->measure_dict, values);
        compute_median(prefix->measure_dict, values);
        compute_minimum(prefix->measure_dict, values);

        // clean up
        g_list_free(values);
        close(sock_ip4);
        close(sock_ip6);
		#endif
    }
	return;
}

#ifdef HAVE_LIBNL
/*
 * Get TCP Statistics like TX_ERRORS and RX_ERRORS
 * of an Interface and insert it into the measure_dict
 *
 * */
void get_stats(void *pfx, void *data)
{
    struct nl_sock *sock;
    struct nl_cache *cache;
    struct rtnl_link *link;

    struct src_prefix_list *prefix = pfx;

    if (prefix == NULL || prefix->measure_dict == NULL)
        return;

    // Allocate Socket
    sock = nl_socket_alloc();

    if (!sock)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error creating Socket");
        return;
    }
    // connect Socket
    if(nl_connect(sock, NETLINK_ROUTE) < 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error connecting Socket");
        return;
    }
    // Allocate Link Cache
    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) <0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error allocating Link cache");
        nl_socket_free(sock);
        return;
    }
    // Get Interface by name
    if (!(link = rtnl_link_get_by_name(cache, prefix->if_name)))
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Error getting Interface");
        return;
    }

    insert_errors(prefix->measure_dict, link);

    // clean up
    rtnl_link_put(link);
    nl_cache_put(cache);
    nl_socket_free(sock);
}
#endif

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

	DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Callback invoked.\n");

	if (ctx == NULL)
		return;

	g_slist_foreach(ctx->prefixes, &compute_srtt, NULL);
    g_slist_foreach(ctx->prefixes, &get_stats, NULL);

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Computing Link Usage\n");
    g_slist_foreach(ctx->prefixes, &compute_link_usage, NULL);

	if (MAM_PMEASURE_NOISY_DEBUG2)
	{
		DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Printing summary\n");
		g_slist_foreach(ctx->prefixes, &pmeasure_print_prefix_summary, NULL);
		g_slist_foreach(ctx->ifaces, &pmeasure_print_iface_summary, NULL);
	}

	DLOG(MAM_PMEASURE_NOISY_DEBUG0, "Callback finished.\n\n");
	DLOG(MAM_PMEASURE_NOISY_DEBUG2, "\n\n");
}
