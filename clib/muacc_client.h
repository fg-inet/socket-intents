#ifndef __MUACC_CLIENT_H__
#define __MUACC_CLIENT_H__

/** \file  muacc_client.h
 *  \brief Alternate Socket API, as it can be used by applications
 *
 *	Implements a low-level socket functions with socket context as additional parameter,
 *	and a high-level socketconnect function that returns a newly connected socket or a
 *	socket from an already connected set
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "lib/muacc_util.h"

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

/** wrapper for close, releases muacc context if it is no longer used
 *
 */
int muacc_close(muacc_context_t *ctx,
		int socket);

/** Linked list of socket options to be set */
typedef struct socketopt {
	int 				level;				/**< Level at which the socket option is valid */
	int 				optname;			/**< Identifier of the option */
	void 				*optval;			/**< Pointer to the value */
	socklen_t 			optlen;				/**< Length of the value */
	int					returnvalue;		/**< Return value of setsockopt() if applicable */
	int					flags;				/**< Flags */
	struct socketopt 	*next;				/**< Pointer to the next socket option */
} socketopt_t;

#define SOCKOPT_IS_SET 0x0001 	/**< Sockopt has been set on the socket */
#define SOCKOPT_OPTIONAL 0x0002	/**< If setting the option fails, still continue */

/** Function that returns a connected socket to the given URL
 *  Supply a "-1" socket and URL, type, proto, family to get a new, freshly connected socket
 *  Alternatively, supply an existing socket as representant of a socket set to choose from
 *
 *  @return 0 if successful (socket is from an existing socket set), 1 if successful (socket is new), -1 if fail
 */
int socketconnect(
	int *socket,		/**< [in,out]	Pointer to representant of a socket set. "-1" if none exists */
	const char *url,	/**< [in]		URL to connect to. May be NULL if socket exists */
	struct socketopt *sockopts,	/**< [in,out]	List of socket options to be set. May be NULL if socket exists */
	int domain,			/**< [in]		Address family for socket() call (e.g. AF_INET, AF_INET6) */
	int type,			/**< [in]		Type for socket() call (e.g. SOCK_STREAM or SOCK_DGRAM */
	int proto			/**< [in]		Protocol for socket() call */
);

#endif
