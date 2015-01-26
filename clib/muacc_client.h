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
#include <pthread.h>

#include "muacc_util.h"

/** Context of a socket on the client side */
typedef struct muacc_context
{
    int     usage;              /**< reference counter */
    uint8_t locks;              /**< lock to avoid multiple concurrent requests */
    int     mamsock;            /**< socket to talk to MAM */
    struct _muacc_ctx *ctx;     /**< internal struct with relevant socket context data */
} muacc_context_t;

typedef struct socketset
{
	int		file;				/**< File descriptor */
	uint8_t locks;              /**< lock to avoid concurrent usage - 0 = free, 1 = in use */
	struct	_muacc_ctx *ctx;
	struct	socketset *next;
} socketset_t;

typedef struct socketlist
{
	struct socketset 	*set;
	struct socketlist 	*next;
} socketlist_t;

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

/** Function that returns a connected socket to the given URL
 *  Supply a "-1" socket and URL, type, proto, family to get a new, freshly connected socket
 *  Alternatively, supply an existing socket as representant of a socket set to choose from
 *  If your supplied socket is not part of a socket set, a new socket will be created and returned!
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

/** Parse a URL and send a socketconnect request to MAM
 *
 *  @return 1 if successful, -1 if fail
 */
int _socketconnect_request(muacc_context_t *ctx, int *s, const char *url);

/** Send a socketchoose request to MAM
 *
 *  @return 0 if existing socket was chosen, 1 if new socket was created, -1 if fail
 */
int _socketchoose_request(muacc_context_t *ctx, int *s, struct socketlist *slist);

/** Process a socketconnect response, create a new socket, bind and connect it
 *
 *  @return 1 if successful, -1 if fail
 */
int _muacc_socketconnect_create(muacc_context_t *ctx, int *s);

/** Send a socketchoose request or open a new socket
 *
 *  @return 0 if successful, -1 if fail
 */
int _socketchoose_request(muacc_context_t *ctx, int *s, struct socketlist *slist);

/** Close a socket that was supplied by socketconnect, drop it from the socket set
 *
 *  @return 0 if successful, -1 if fail
 */
int socketclose(int socket);

/** Release a socket, marking it as no longer in use within its socket set, so it can be reused from now on
 *
 *  @return 0 if successful, -1 if fail
 */
int socketrelease(int socket);

#endif
