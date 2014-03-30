/** \file  muacc_client_util.h
 *  \brief Helper functions used by the muacc client
 */
#ifndef __MUACC_CLIENT_UTIL_H__
#define __MUACC_CLIENT_UTIL_H__

#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "muacc_client.h"

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

#endif /* __MUACC_CLIENT_UTIL_H__ */
