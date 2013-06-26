/** \file policy_util.h
 *  \brief Utilities for writing MAM policies
 */

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

