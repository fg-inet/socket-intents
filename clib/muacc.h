#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef _MUACC_CTX_
#define _MUACC_CTX_

#define MUACC_TLV_LEN 2048

typedef struct muacc_context 
{
	struct _muacc_ctx *ctx;
} muacc_context_t;

/** initialize background structures for muacc_context
 *
 * @return 0 on success, -1 otherwise
 */ 
int muacc_init_context(struct muacc_context *ctx);

/** make a deep copy of a muacc_context
 *
 * @return 0 on success, -1 otherwise
 */ 
int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src);
 
/** increase reference counter for muacc_context 
  *
  * @return current reference count
  */
int muacc_retain_context(struct muacc_context *ctx);

/** print contents of the internal data structure of the context
 *
 */
void muacc_print_context(struct muacc_context *ctx);

/** decrease reference for muacc_context and free background structures if it reaches 0
  *
  * @return current reference count or -1 if context was NULL
  */
int muacc_release_context(struct muacc_context *ctx);

/** wrapper for getaddrinfo using mam instead of resolver library and updating ctx
 *
 */
int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res);

/** wrapper for setsockopt, sets intent sockopts in context or calls original
 *
 */
int muacc_setsockopt(struct muacc_context *ctx,
        int socket, int level, int option_name,
        const void *option_value, socklen_t option_len);

/** wrapper for getsockopt, returns intent sockopt or calls original getsockopt
 *
 */
int muacc_getsockopt(struct muacc_context *ctx,
	int socket, int level, int option_name,
	void *option_value, socklen_t *option_len);

/** wrapper for connect using info from ctx
 *
 */
int muacc_connect(struct muacc_context *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len);

#endif
