
#ifndef __MUACC_UTIL_H__
#define __MUACC_UTIL_H__

#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

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

void _muacc_print_sockaddr(struct sockaddr *addr, size_t src_len);

void _muacc_print_addrinfo(struct addrinfo *addr);

void _muacc_print_socket_options(struct socketopt *opts);


#endif /* __MUACC_UTIL_H__ */
