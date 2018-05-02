/** \file policy_earliest_arrival.h
 *  \brief Policy that calculates the predicted completion time for an object on all prefixes and selects the fastest
 *
 *  \copyright Copyright 2013-2016 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
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
};

double EPSILON = 0.0001;

double get_srtt(struct src_prefix_list *pfx, strbuf_t *sb);
double get_max_rate(struct src_prefix_list *pfx, strbuf_t *sb);
double get_rate(struct src_prefix_list *pfx, strbuf_t *sb);
double get_capacity(struct src_prefix_list *pfx, double max_rate, double rate, strbuf_t *sb);
double predict_completion_time(struct src_prefix_list *pfx, int filesize, int reuse, strbuf_t *sb);

struct src_prefix_list *get_src_prefix(request_context_t *rctx, int reuse, strbuf_t *sb);
struct src_prefix_list *get_fastest_prefix(GSList *spl);
struct src_prefix_list *get_default_prefix(request_context_t *rctx, GSList *in4_enabled, GSList *in6_enabled, strbuf_t *sb);

int resolve_name(request_context_t *rctx);
