/** \file  muacc_client_util.h
 *  \brief Helper functions used by the muacc client
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef MUACC_CLIENT_UTIL_H
#define MUACC_CLIENT_UTIL_H

#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "socketset.h"

#include "muacc.h"

/** Context of a socket on the client side */
typedef struct muacc_context
{
    int     usage;              /**< reference counter */
    uint8_t locks;              /**< lock to avoid multiple concurrent requests */
    int     mamsock;            /**< socket to talk to MAM */
    struct _muacc_ctx *ctx;     /**< internal struct with relevant socket context data */
} muacc_context_t;

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

/** Process a socketconnect response, create a new socket, bind and connect it. Append it to set list my_socksetlist and use my_socksetlist_lock for that, if not NULL.
 *
 *  @return 1 if successful, -1 if fail
 */
int _muacc_socketconnect_create(muacc_context_t *ctx, int *s, struct socketset **my_socketsetlist, pthread_rwlock_t *my_socketsetlist_lock, int create_nonblock_socket);


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

/** Send socketchoose request and process response
 *
 * @return 0 for choosing existing socket, 1 for opening new socket, -1 otherwise
 */
int _muacc_send_socketchoose (muacc_context_t *ctx, int *socket, struct socketset *set);

/** Copy a host name to the context, and resolve its service name to a port number
 *
 * @return 0 on success, -1 otherwise
 */
int _muacc_host_serv_to_ctx(muacc_context_t *ctx, const char *host, size_t hostlen, const char *serv, size_t servlen);

#endif /* __MUACC_CLIENT_UTIL_H__ */
