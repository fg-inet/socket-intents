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

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/idiag/idiagnl.h>
#include <netlink/idiag/vegasinfo.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>

#ifndef MAM_PMEASURE_NOISY_DEBUG0
#define MAM_PMEASURE_NOISY_DEBUG0 1
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG1
#define MAM_PMEASURE_NOISY_DEBUG1 1
#endif

#ifndef MAM_PMEASURE_NOISY_DEBUG2
#define MAM_PMEASURE_NOISY_DEBUG2 1
#endif


#define BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
#define TCPF_ALL 0xFFF


int compare_ip (struct sockaddr *a1, struct sockaddr *a2);
int is_addr_in_pfx (const void *a, const void *b);
void compute_median(GHashTable *dict, GList *values);
void compute_mean(GHashTable *dict, GList *values);
void compute_minimum(GHashTable *dict, GList *values);
int create_nl_sock();
GList * parse_nl_msg(struct inet_diag_msg *pMsg, int rtalen, void *pfx, GList *values);
int send_nl_msg(int sock, int i);
int recv_nl_msg(int sock, void *pfx, GList **values);
void compute_srtt(void *pfx, void *data);
void insert_errors(GHashTable *pTable, struct rtnl_link *pLink);
void get_stats(void *pfx, void *data);

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
    double alpha = 0.9;


    int n = g_list_length(values);
    DLOG(MAM_PMEASURE_NOISY_DEBUG1, "List for interface has length %d\n", n);

    meanvalue = g_hash_table_lookup(dict, "srtt_mean");


    if (meanvalue == NULL)
    {
        meanvalue = malloc(sizeof(double));
        memset(meanvalue, 0, sizeof(double));
        g_hash_table_insert(dict, "srtt_mean", meanvalue);
    }

    if (n == 0)
    {
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "List is empty, there is no mean value.\n");
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

    // calculate SRTT in accord with the formula
    // SRTT = (alpha * SRTT) + ((1-alpha) * RTT)
    // see RFC793
    *meanvalue = (alpha * *meanvalue) + ((1-alpha) * old_rtt);

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List of length %d has mean value %f \n", n, *meanvalue);
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
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "List is empty, there is no median value.\n");
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
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "List is empty, there is no minimum value.\n");
        *minimum = 0;
        return;
    }
    else
    {
        *minimum = *(double *) g_list_first(values)->data;
    }

    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "List of length %d has minimum value %f \n", n, *minimum);
}

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
    DLOG(MAM_PMEASURE_NOISY_DEBUG2,"Added %d as TX_ERRORS\n", *tx_errors);
    *rx_errors = rtnl_link_get_stat(link,RTNL_LINK_RX_PACKETS);
    DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Added %d as RX_ERRORS\n", *rx_errors);
}

/** Print the flow table of every prefix that has one,
 *  and the mean and median RTTs if they exist
 */
void pmeasure_print_summary(void *pfx, void *data)
{
	struct src_prefix_list *prefix = pfx;

	if (prefix == NULL || prefix->measure_dict == NULL)
		return;
    printf("Summary for interface: %s, Family: %s\n", prefix->if_name, prefix->family == AF_INET?"IPv4":"IPv6");
	double *meanvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_mean");
	if (meanvalue != NULL)
		printf("\tMean SRTT: %f ms\n", *meanvalue);

	double *medianvalue = g_hash_table_lookup(prefix->measure_dict, "srtt_median");
	if (medianvalue != NULL)
		printf("\tMedian SRTT: %f ms\n", *medianvalue);


    uint64_t  *rx_errors = g_hash_table_lookup(prefix->measure_dict, "rx_errors");
    if (rx_errors != NULL)
        printf("\tRX Errors: %d \n", *rx_errors);

    uint64_t *tx_errors = g_hash_table_lookup(prefix->measure_dict, "tx_errors");
    if (medianvalue != NULL)
        printf("\tTX Errors: %d \n", *tx_errors);

	printf("\n");
}

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

    // create sockaddr out of the message to compare it to pfx

    char str[INET6_ADDRSTRLEN];
    memset(&str, 0, sizeof(str));

    if(msg->idiag_family == AF_INET)
    {
        msg_addr_v4.sin_family = msg->idiag_family;
        msg_addr_v4.sin_port = msg->id.idiag_sport;
        inet_ntop(AF_INET, &(msg->id.idiag_src), str, INET_ADDRSTRLEN);
        inet_pton(AF_INET, str, &(msg_addr_v4.sin_addr));

    } else if(msg->idiag_family == AF_INET6)
    {
        msg_addr_v6.sin6_family = AF_INET6;
        msg_addr_v6.sin6_port = msg->id.idiag_sport;
        inet_ntop(AF_INET6, (struct in_addr6 *) &(msg->id.idiag_src), str, INET6_ADDRSTRLEN);
        inet_pton(AF_INET6, str,  &(msg_addr_v6.sin6_addr));
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
        DLOG(MAM_PMEASURE_NOISY_DEBUG1,"%s IS in the Prefixlist!\n", str);

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
                DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Adding %f to values\n", rtt);
                values = g_list_append(values, &rtt);

                DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Values has now length %d\n", g_list_length(values));
            }
            //Get next attributes
            attr = RTA_NEXT(attr, rtalen);
        }
        }
    return values;


}

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
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Computing median SRTTs for a prefix of interface %s:\n", prefix->if_name);

        // create the socket
        int sock = create_nl_sock();
        if (sock == EXIT_FAILURE)
        {
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Socket creation failed");
        }
        // Create and send netlink messages
        // we have to send two different requests, the first time
        // with the IPv4 Flag and the other time with the IPv6 flag
        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Sending IPv4 Request\n");
        if (send_nl_msg(sock, AF_INET) == -1)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, " Error sending Netlink Request");

        // receive messages
        if (recv_nl_msg(sock, prefix, &values) != 0)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error receiving Netlink Messages")

        DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Sending IPv6 Request\n");
        if (send_nl_msg(sock, AF_INET6) == -1)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, " Error sending Netlink Request");

        // receive messages
        if (recv_nl_msg(sock, prefix, &values) != 0)
            DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Error receiving Netlink Messages");

        // compute mean, median and minimum out of the
        // rtt values and write it into the dict
        compute_mean(prefix->measure_dict, values);
        compute_median(prefix->measure_dict, values);
        compute_minimum(prefix->measure_dict, values);

        // clean up
        g_list_free(values);
        close(sock);
    }
	return;
}

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
    g_slist_foreach(ctx->prefixes, &get_stats, NULL);
	if (MAM_PMEASURE_NOISY_DEBUG2)
	{
		DLOG(MAM_PMEASURE_NOISY_DEBUG2, "Printing summary\n");
		g_slist_foreach(ctx->prefixes, &pmeasure_print_summary, NULL);
	}

	DLOG(MAM_PMEASURE_NOISY_DEBUG1, "Callback finished.\n\n");
}
