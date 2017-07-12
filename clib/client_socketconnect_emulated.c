/** \file client_socketconnect_emulated.c
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt,
 *  Mirko Palmer, and Tobias Kaiser.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <assert.h>

#include "lib/dlog.h"
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"
#include "lib/intents.h"

#include "client_util.h"
#include "muacc_util.h"
#include "client_socketconnect_async.h"
#include "config.h"

int muacc_sce_socketconnect(
	int *socket, const char *host, size_t hostlen, const char *serv,
	size_t servlen, struct socketopt *sockopts,
	int domain,	int type, int proto
)
{
	int ret;

	ret = muacc_sca_socketconnect(socket, host, hostlen, serv, servlen, sockopts, domain, type, proto);

	if(ret==-1) {
		return ret;
	}

	int finished_waiting;
	do {
		fd_set r_fds, w_fds, x_fds;
		
		FD_ZERO(&r_fds);
		FD_ZERO(&w_fds);
		FD_ZERO(&x_fds);

		FD_SET(*socket, &w_fds); /* We can dereferentiate socket here, because if it is NULL, we would already have returned -1 above */
		FD_SET(*socket, &x_fds);  

		muacc_sca_socketselect(FD_SETSIZE, &r_fds, &w_fds, &x_fds, NULL);

		finished_waiting=0;

		if(FD_ISSET(*socket, &w_fds)) {
			finished_waiting=1;
		}
		if(FD_ISSET(*socket, &x_fds)) {
			finished_waiting=1;
		}
	} while(!finished_waiting);

	return 0; /* TODO: How about error handling? */
}

/* 1:1 mapping for muacc_sce_socket{close,release,cleanup} to muacc_sca_... */

int muacc_sce_socketclose(int socket)
{
	return muacc_sca_socketclose(socket);
}

int muacc_sce_socketrelease(int socket)
{
	return muacc_sca_socketrelease(socket);
}

int muacc_sce_socketcleanup(int socket)
{
	return muacc_sca_socketcleanup(socket);

}

