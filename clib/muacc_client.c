/** \file muacc_client.c
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "dlog.h"

#include "intents.h"

#include "client_util.h"
#include "muacc_util.h"
#include "muacc_client.h"

#ifndef CLIB_IF_NOISY_DEBUG0
#define CLIB_IF_NOISY_DEBUG0 0
#endif

#ifndef CLIB_IF_NOISY_DEBUG1
#define CLIB_IF_NOISY_DEBUG1 0
#endif

#ifndef CLIB_IF_NOISY_DEBUG2
#define CLIB_IF_NOISY_DEBUG2 0
#endif


pthread_rwlock_t socketsetlist_lock_old = PTHREAD_RWLOCK_INITIALIZER;
struct socketset *socketsetlist_old = NULL;


int muacc_socket(muacc_context_t *ctx,
        int domain, int type, int protocol)
{
	return muacc_sa_socket(ctx, domain, type, protocol);
}

int muacc_getaddrinfo(muacc_context_t *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res)
{
	return muacc_sa_getaddrinfo(ctx, hostname, servname, hints, res);
}


int muacc_setsockopt(muacc_context_t *ctx, int socket, int level, int option_name,
    const void *option_value, socklen_t option_len)
{
    return muacc_sa_setsockopt(ctx, socket, level, option_name, option_value, option_len);
}

int muacc_getsockopt(muacc_context_t *ctx, int socket, int level, int option_name,
    void *option_value, socklen_t *option_len)
{
    return muacc_sa_getsockopt(ctx, socket, level, option_name, option_value, option_len);
}

int muacc_bind(muacc_context_t *ctx, int socket, const struct sockaddr *address, socklen_t address_len)
{
    return muacc_sa_bind(ctx, socket, address, address_len);
}

int muacc_connect(muacc_context_t *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len)
{
    return muacc_sa_connect(ctx, socket, address, address_len);
}

int muacc_close(muacc_context_t *ctx,
        int socket)
{
    return muacc_sa_close(ctx, socket);
}

int socketconnect(int *s, const char *host, size_t hostlen, const char *serv, size_t servlen, struct socketopt *sockopts, int domain, int type, int proto)
{
    return muacc_sc_socketconnect(s, host, hostlen, serv, servlen, sockopts, domain, type, proto);
}

int socketclose(int socket)
{
    return muacc_sc_socketclose(socket);
}

int socketrelease(int socket)
{
    return muacc_sc_socketrelease(socket);
}

int socketcleanup(int socket)
{
    return muacc_sc_socketcleanup(socket);
}
