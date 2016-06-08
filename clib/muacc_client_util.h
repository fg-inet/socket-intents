/** \file  muacc_client_util.h
 *  \brief Helper functions used by the muacc client
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef __MUACC_CLIENT_UTIL_H__
#define __MUACC_CLIENT_UTIL_H__

#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "muacc_client.h"

/* socketlist lock */
#ifndef CLIB_IF_LOCKS
#define CLIB_IF_LOCKS 0
#endif

extern struct socketset *socketsetlist;
extern pthread_rwlock_t socketsetlist_lock;

/** initialize background structures for muacc_context
 *
 * @return 0 on success, -1 otherwise
 */
int muacc_init_context(muacc_context_t *ctx);

/** Helper to retrieve the inode of the socket
 *
 * @return inode number of the given socket
 */
muacc_ctxino_t _muacc_get_ctxino(int sockfd);

/** Helper doing locking simulation - lock part
 *
 * just to make sure that we have no
 * interleaving requests on a single socket
 */
int _lock_ctx (muacc_context_t *ctx);

/** Helper doing locking simulation - unlock part
 *
 * just to make sure that we have no
 * interleaving requests on a single socket
 */
int _unlock_ctx (muacc_context_t *ctx);

/** Helper to check if a socket was closed from the remote side
 *
 * Tries to recv a byte from the socket (with MSG_PEEK so
 * it can be re-read by the next recv())
 * If it returns 0 we know the remote side has send FIN,ACK
 * so it wants to close the socket.
 */
int _is_socket_open(int sockfd);

/** make a deep copy of a muacc_context
 *
 * @return 0 on success, -1 otherwise
 */
int muacc_clone_context(muacc_context_t *dst, muacc_context_t *src);

/** increase reference counter for muacc_context
  *
  * @return current reference count
  */
int muacc_retain_context(muacc_context_t *ctx);

/** print contents of the internal data structure of the context
 *
 */
void muacc_print_context(muacc_context_t *ctx);

/** decrease reference for muacc_context and free background structures if it reaches 0
  *
  * @return current reference count or -1 if context was NULL
  */
int muacc_release_context(muacc_context_t *ctx);

/** speak the TLV protocol as a client to make MAM update _ctx with her wisdom
 *
 * @return 0 on success, a negative number otherwise
 */
int _muacc_contact_mam (
	muacc_mam_action_t reason,	/**< [in]	reason for contacting */
	muacc_context_t *ctx		/**< [in]	context to be updated */
);

/** make the TLV client ready by establishing a connection to MAM
 *
 * @return 0 on success, a negative number otherwise
 */
int _muacc_connect_ctx_to_mam(muacc_context_t *ctx) ;

/** Add a Socket Intent to a socket options list
 *
 *  @return 0 on success, a negative number otherwise
 */
int muacc_set_intent(socketopt_t **opts, int optname, const void *optval, socklen_t optlen, int flags);

/** Free a list of socket options
 *
 * @return 0 on success, a negative number otherwise
 */
int muacc_free_socket_option_list(socketopt_t *opts);

/** Add socket to a socketset
 *
 * @return 0 on success, a negative number otherwise
 */
struct socketset* _muacc_add_socket_to_set(struct socketset **list_of_sets, int socket, struct _muacc_ctx *ctx);

/** Find the socket set that contains the socket with the given file descriptor, if any
 *
 * @return Pointer to the socket set that contains the socket, if found, or NULL
 */
struct socketset *_muacc_find_socketset(struct socketset *list_of_sets, int socket);

/** Find a socket set that matches the socket context
 *
 * @return Pointer to the socket set if found, or NULL
 */
struct socketset *_muacc_find_set_for_socket(struct socketset *list_of_sets, struct _muacc_ctx *ctx);

/** Print the list of socket sets
 *
 */
void muacc_print_socketsetlist(struct socketset *list_of_sets);

/** Print a socket set
 *
 */
void muacc_print_socketset(struct socketset *set);

/** Send socketchoose request and process response
 *
 * @return 0 for choosing existing socket, 1 for opening new socket, -1 otherwise
 */
int _muacc_send_socketchoose (muacc_context_t *ctx, int *socket, struct socketset *set);

/** Find socketset that is a duplicate of the given one (i.e. has different file descriptor but same context)
 * 
 *  @return next duplicate socket set, or NULL if none exists
 */
struct socketlist *_muacc_socketset_find_dup (struct socketlist *slist);

/** Find the previous socket set in the list
 *
 * @return Pointer to the previous socket set (or NULL, if this is the first set in the list)
 */
struct socketset *_muacc_find_prev_socketset(struct socketset **list_of_sets, struct socketset *set);

/** Remove socket from set, and clean up socketset if set is now empty
 *
 * @return 0 on success, -1 otherwise
 */
int _muacc_remove_socket_from_list (struct socketset **list_of_sets, int socket);

/** Copy a host name to the context, and resolve its service name to a port number
 *
 * @return 0 on success, -1 otherwise
 */
int _muacc_host_serv_to_ctx(muacc_context_t *ctx, const char *host, size_t hostlen, const char *serv, size_t servlen);

/** Free a socket from a socket set, and close its file descriptor.
 *
 *  @return 0 on success (set still has sockets), 1 on success (set is empty now), -1 otherwise
 */
int _muacc_free_socket(struct socketset *set_to_delete, struct socketlist *socket_to_delete, struct socketlist *prevlist);

/** Clean up unused sockets from a socket set
 *
 * @return 0 on success, -1 otherwise
 */
int _muacc_cleanup_sockets(struct socketset **set);

#endif /* __MUACC_CLIENT_UTIL_H__ */
