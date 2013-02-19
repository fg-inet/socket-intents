
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

size_t _muacc_print_sockaddr(char *buf, size_t *buf_pos, size_t buf_len, const struct sockaddr *addr, size_t src_len);

size_t _muacc_print_addrinfo(char *buf, size_t *buf_pos, size_t buf_len, const struct addrinfo *addr);

/** helper to print a list of socket options
 *
 */
void _muacc_print_socket_option_list(const struct socketopt *opts);

size_t _muacc_print_socket_options(char *buf, size_t *buf_pos, size_t buf_len, const struct socketopt *opts);


#endif /* __MUACC_UTIL_H__ */
