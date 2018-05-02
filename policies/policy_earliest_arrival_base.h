/** \file policy_earliest_arrival_base.c
 *  \brief Base functions for Earliest Arrival Policy. Leaves the actual prediction up to the policy implemented elsewhere.
 *
 *  \copyright Copyright 2013-2016 Philipp Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Behavior:
 *  Getaddrinfo   - Resolve names using the default dns_base from the MAM context
 *  Connect       - Choose the prefix with the shortest predicted completion time
 *  Socketconnect - Choose the prefix with the shortest predicted completion time and resolve name on it
 *  Socketchoose  - Choose a socket on the prefix with the shortest predicted completion time
 */

#include "policy.h"
#include "policy_util.h"
#include <time.h>

/** Policy-specific per-prefix data structure that contains additional information */
struct eafirst_info {
	int is_default;              /** 1 if the prefix has been specified as default in the config file */
	double predicted_time;       /** estimated completion time for current object on this prefix */
    int count;                  /** count per prefix */
    int count_prev;             /** count per prefix on previous call (not always used) */
    int count_small;            /** counter per prefix */
    int reuse;                  /** counter of sockets ready for reuse */
    int reuse_prev;             /** counter of reuse sockets already seen in the last call */
	int sockets_big[MAX_NUM_CONNS];	/** Which sockets were scheduled with big objects */
	int sockets_small[MAX_NUM_CONNS];	/** Which sockets were scheduled with small objects */
    double sockettimestamps[MAX_NUM_CONNS]; /** Timestamps when socket was either scheduled or seen as available */
    void *additional_info;      /** additional information per prefix */
};

// The following functions are generic and defined in policy_earliest_arrival_base.c
struct src_prefix_list *get_src_prefix(request_context_t *rctx, strbuf_t *sb);
struct src_prefix_list *get_fastest_prefix(GSList *spl);
struct src_prefix_list *get_default_prefix(GSList *spl, request_context_t *rctx, strbuf_t *sb);
int resolve_name(request_context_t *rctx);

// The following functions are specific to a variant of the Earliest Arrival Policy
// so each incarnation can determine how it actually does the prediction
double get_srtt(struct src_prefix_list *pfx, strbuf_t *sb);
double get_max_rate(struct src_prefix_list *pfx, strbuf_t *sb);
double get_rate(struct src_prefix_list *pfx, strbuf_t *sb);
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb);
struct src_prefix_list *get_best_prefix(GSList *spl, int filesize, request_context_t *rctx, const char *logfile, strbuf_t *sb);
double predict_completion_time(struct src_prefix_list *pfx, int filesize, int reuse, strbuf_t *sb);
void choose_this_prefix(struct request_context *rctx, struct src_prefix_list *bind_pfx, strbuf_t *sb);

void set_reuse_count (GSList *spl, request_context_t *rctx);

static const char *logfile = NULL;
