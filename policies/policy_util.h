/** \file policy_util.h
 *  \brief Utilities for writing MAM policies
 */

#include "mam/mam.h"
#include "lib/muacc_util.h"
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
