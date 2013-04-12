/** \file  muacc_client.h
 *  \brief Alternate Socket API, extended by muacc context
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "../lib/muacc.h"

#ifndef __MUACC_CLIENT_H__
#define __MUACC_CLIENT_H__

/** Context of a socket on the client side */
typedef struct muacc_context
{
    int     usage;              /**< reference counter */
    uint8_t locks;              /**< lock to avoid multiple concurrent requests */
    int     mamsock;            /**< socket to talk to MAM */
    struct _muacc_ctx *ctx;     /**< internal struct with relevant socket context data */
} muacc_context_t;

/** wrapper for socket, initializes an uninitialized context
 *
 */
int muacc_socket(muacc_context_t *ctx,
		int domain, int type, int protocol);

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

/** wrapper for bind, calls original bind and records to ctx 
 *
 */
int muacc_bind(muacc_context_t *ctx, int socket, const struct sockaddr *address, socklen_t address_len);

/** wrapper for connect using info from ctx
 *
 */
int muacc_connect(muacc_context_t *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len);

/* wrapper for close, releases muacc context if it is no longer used
 *
 */
int muacc_close(muacc_context_t *ctx,
		int socket);

#endif
