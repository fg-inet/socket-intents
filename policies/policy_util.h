/** \file policy_util.h
 *  \brief Utilities for writing MAM policies
 */

/** Look up a socket option in a list of socketopts, copy its value into optval
 *  If optval is NULL, only look up if the option exists, but do not copy its value
 *
 *  \return 0 if option was found, -1 if option was not found
 */
int mampol_get_socketopt(struct socketopt *list, int level, int optname, socklen_t *optlen, void *optval);

/** Look up a prefix of a certain interface name and address family in the prefix list
 *
 *  \return 0 if a suitable prefix is found, -1 otherwise
 */
int mampol_get_prefix_by_name(struct src_prefix_list *list, const char *name, int family, struct src_prefix_list **pref);

/** Suggest a sockaddr with this interface name to the client */
int mampol_suggest_bind_sa(request_context_t *rctx, const char *name);
