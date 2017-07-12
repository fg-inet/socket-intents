#ifndef MUACC_CLIENT_SOCKETCONNECT_EMULATED_H
#define MUACC_CLIENT_SOCKETCONNECT_EMULATED_H

/** \file  client_socketconnect_emulated.h
 *  \brief Socketconnect API
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt,
 *  Mirko Palmer, and Tobias Kaiser.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Implements a high-level socketconnect function that returns a newly connected socket or a
 *  socket from an already connected set. Emulates the blocking socketconnect API through the
 *  non-blocking version.
 */

#include "client_util.h"

extern struct socketset *socketsetlist;
extern pthread_rwlock_t socketsetlist_lock;

/** Function that returns a connected socket to the given URL
 *  Supply a "-1" socket and URL, type, proto, family to get a new, freshly connected socket
 *  Alternatively, supply an existing socket as representant of a socket set to choose from
 *  If your supplied socket is not part of a socket set, a new socket will be created and returned!
 *
 *  @return 0 if successful (socket is from an existing socket set), 1 if successful (socket is new), -1 if fail
 */
int muacc_sce_socketconnect(
	int *socket,		/**< [in,out]	Pointer to representant of a socket set. "-1" to create a new socket, "0" will try to find a suitable socket set for the request */
	const char *host,	/**< [in]		Host name to connect to */
	size_t hostlen,
	const char *serv,	/**< [in]		Service or port (in ASCII) to connect to */
	size_t servlen,
	struct socketopt *sockopts,	/**< [in,out]	List of socket options to be set. May be NULL if socket exists */
	int domain,			/**< [in]		Address family for socket() call (e.g. AF_INET, AF_INET6) */
	int type,			/**< [in]		Type for socket() call (e.g. SOCK_STREAM or SOCK_DGRAM */
	int proto			/**< [in]		Protocol for socket() call */
);

/** Close a socket that was supplied by socketconnect, drop it from the socket set
 *
 *  @return 0 if successful, -1 if fail
 */
int muacc_sce_socketclose(int socket);

/** Release a socket, marking it as no longer in use within its socket set, so it can be reused from now on
 *
 *  @return 0 if successful, -1 if fail
 */
int muacc_sce_socketrelease(int socket);

/** Closes a socket and cleans up all unused sockets from its socket set
 *
 *  @return 0 if successful, -1 if fail
 */
int muacc_sce_socketcleanup(int socket);


#endif