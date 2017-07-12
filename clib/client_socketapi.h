#ifndef MUACC_CLIENT_SOCKETAPI_H
#define MUACC_CLIENT_SOCKETAPI_H

/** \file  client_socketapi.h
 *  \brief Alternate Socket API, as it can be used by applications
 *
*  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt,
 *  Mirko Palmer, and Tobias Kaiser.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *	Implements a low-level socket functions with socket context as additional parameter,
 *	and a high-level socketconnect function that returns a newly connected socket or a
 *	socket from an already connected set
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

#include "client_util.h"

#include "muacc_util.h"


/** wrapper for socket, initializes an uninitialized context
 *
 */
int muacc_sa_socket(muacc_context_t *ctx,
		int domain, int type, int protocol);

/** wrapper for getaddrinfo using mam instead of resolver library and updating ctx
 *
 */
int muacc_sa_getaddrinfo(muacc_context_t *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res);

/** wrapper for setsockopt, sets intent sockopts in context or calls original
 *
 */
int muacc_sa_setsockopt(muacc_context_t *ctx,
        int socket, int level, int option_name,
        const void *option_value, socklen_t option_len);

/** wrapper for getsockopt, returns intent sockopt or calls original getsockopt
 *
 */
int muacc_sa_getsockopt(muacc_context_t *ctx,
	int socket, int level, int option_name,
	void *option_value, socklen_t *option_len);

/** wrapper for bind, calls original bind and records to ctx 
 *
 */
int muacc_sa_bind(muacc_context_t *ctx, int socket, const struct sockaddr *address, socklen_t address_len);

/** wrapper for connect using info from ctx
 *
 */
int muacc_sa_connect(muacc_context_t *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len);

/** wrapper for close, releases muacc context if it is no longer used
 *
 */
int muacc_sa_close(muacc_context_t *ctx,
		int socket);


#endif