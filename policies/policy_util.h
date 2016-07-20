/** \file policy_util.h
 *  \brief Utilities for writing MAM policies
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "mam/mam.h"
#include "clib/muacc_util.h"
#include "lib/muacc_ctx.h"
#include "policy.h"

#define test_if_in6_is_equal(a, b) (memcmp(&(a), &(b), sizeof(struct in6_addr)) == 0)

/** Look up a socket option in a list of socketopts, copy its value into optval
 *  If optval is NULL, only look up if the option exists, but do not copy its value
 *
 *  \return 0 if option was found, -1 if option was not found
 */
int mampol_get_socketopt(struct socketopt *list, int level, int optname, socklen_t *optlen, void *optval);

/** Print the information of a policy_info struct
 *  Implementation is policy-specific
 */
void print_policy_info(void *policy_info);

/** For an element from the prefix list, print its first address
 *  and its policy data if available
 */
void print_pfx_addr (gpointer element, gpointer data);

/** Convenience function that builds lists of available IPv4 and IPv6 addresses
 *  and prints them */
void make_v4v6_enabled_lists (GSList *baselist, GSList **v4list, GSList **v6list);

/** Helper that sets the suggested binding source address in the request context
 *  to the first address of the chosen prefix
 */
void set_bind_sa(request_context_t *rctx, struct src_prefix_list *chosen, strbuf_t *sb);
void _set_bind_sa(request_context_t *rctx, struct sockaddr *addr, strbuf_t *sb);

/** Helper that prints the addresses returned by getaddrinfo */
void print_addrinfo_response (struct addrinfo *res);

/** Helper that searches for information for a prefix in various dictionaries */
void *lookup_prefix_info(struct src_prefix_list *prefix, const void *key);

/** Helper that looks if the socketlist contains a socket on a particular prefix
 *	Returns 0 if no socket is found, 1 if at least one socket is found
  */
  int is_there_a_socket_on_prefix(struct socketlist *list, struct src_prefix_list *pfx);

/** Helper that filters a socket list for a particular prefix */
void pick_sockets_on_prefix(request_context_t *rctx, struct src_prefix_list *bind_pfx);

/** Helper that returns the prefix with a given socket address */
struct src_prefix_list *get_pfx_with_addr(request_context_t *rctx, struct sockaddr *addr);
