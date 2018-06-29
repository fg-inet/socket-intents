/** \file  muacc_util.h
 *  \brief Helper functions used by the muacc library that do not manipulate the muacc ctx directly
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef __MUACC_UTIL_H__
#define __MUACC_UTIL_H__

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "muacc.h"

/** helper that logs to a file
 *
 */
void _muacc_logtofile (const char *filename, const char *format, ...);

/** helper to copy a cstring
 *
 */
char *_muacc_clone_string(const char *src);

/** helper to deep copy sockaddr structs
 *
 */
struct sockaddr *_muacc_clone_sockaddr(const struct sockaddr *src, size_t src_len);

/** helper to deep copy addrinfo structs
 *
 */
struct addrinfo *_muacc_clone_addrinfo(const struct addrinfo *src);

/** helper to deep copy socketopt linked lists
 *
 */
struct socketopt *_muacc_clone_socketopts(const struct socketopt *src);

/** helper to deep copy a _muacc_ctx
 *
 */
struct _muacc_ctx *_muacc_clone_ctx(struct _muacc_ctx *origin);

/** helper to deep free socketopt linked lists
 *
 */
void _muacc_free_socketopts(struct socketopt *so);

/** helper to print a sockaddr into a string
 *
 */
void _muacc_print_sockaddr(strbuf_t *sb, const struct sockaddr *addr, size_t src_len);

/** helper to print a addrinfo list into a string
 *
 */
void _muacc_print_addrinfo(strbuf_t *sb, const struct addrinfo *addr);

/** helper to print a list of socket options
 *
 */
void _muacc_print_socket_option_list(const struct socketopt *opts);

/** helper to print a list of socket options into a string
 *
 */
void _muacc_print_socket_options(strbuf_t *sb, const struct socketopt *opts);

/** helper to print out a sockaddr
 *
 */
void _muacc_print_socket_addr(const struct sockaddr *addr, size_t addr_len);

/** helper to print a socket option into a string
 *
 */
void _muacc_print_socket_option(strbuf_t *sb, const struct socketopt *current);


/** helper to avoid having to link the uuid lib into the client
 *
 */
void __uuid_copy(uuid_t dst, uuid_t src);
int  __uuid_compare(uuid_t a, uuid_t b);
int  __uuid_is_null(uuid_t uuid);
void __uuid_unparse_lower(const uuid_t uuid, char* dst);

/** helper to set a socket option in a socketopt list
 *
 */
int _muacc_add_sockopt_to_list(socketopt_t **opts, int level, int optname, const void *optval, socklen_t optlen, int flags);

#endif /* __MUACC_UTIL_H__ */
