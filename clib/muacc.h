#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef __MUACC_H__
#define __MUACC_H__


typedef struct muacc_context 
{
	struct _muacc_ctx *ctx;
} muacc_context_t;

/** initialize background structures for muacc_context
 *
 * @return 0 on success, -1 otherwise
 */ 
int muacc_init_context(muacc_context_t *ctx);

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

/** wrapper for getaddrinfo using mam instead of resolver library and updating ctx
 *
 */
int muacc_getaddrinfo(muacc_context_t *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res);

/** wrapper for setsockopt, sets intent sockopts in context or calls original
 *
 */
int muacc_setsockopt(muacc_context_t *ctx,
        int socket, int level, int option_name,
        const void *option_value, socklen_t option_len);

/** wrapper for getsockopt, returns intent sockopt or calls original getsockopt
 *
 */
int muacc_getsockopt(muacc_context_t *ctx,
	int socket, int level, int option_name,
	void *option_value, socklen_t *option_len);

/** wrapper for connect using info from ctx
 *
 */
int muacc_connect(muacc_context_t *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len);

#endif
