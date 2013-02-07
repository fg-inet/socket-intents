/** \file testintents.c
 *  \brief Set of unit tests of the intents socket library - to be run with LD_PRELOAD=./libintents.so
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <glib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "../libintents/libintents.h"

/** Fixture = Element used in a set of tests; here: just a socket file descriptor
 *
 */
typedef struct
{
	int sock;
} dfixture;

/** Structure containing a socket option
 *
 */
struct socketoption
{
	int level;
	int optname;
	void *optval;
	socklen_t optlen;
};

/** Helper that creates a socket
 *
 */
void socket_setup(dfixture *df, const void *test_data)
{
	printf("\n===========\n");
	df->sock = socket(AF_INET, SOCK_DGRAM, 0);
}

/** Helper that closes a socket
 *
 */
void socket_close(dfixture *df, const void * test_data)
{
	close(df->sock);
	printf("\n===========\n");
}

/** Helper that compares two socket options and fails if they do not match
 *
 */
void compare_socketoption(const struct socketoption *a, const struct socketoption *b)
{
	g_assert_cmpint((int) a->optlen, ==, (int) b->optlen);
	g_assert( 0 == memcmp(a->optval, b->optval, a->optlen));
}

/** Helper that sets a socket option, then gets it again and compares the two
 *
 */
void setget_sockopt(dfixture *df, const void* param)
{
	const struct socketoption *sent = param;
	setsockopt(df->sock, sent->level, sent->optname, sent->optval, sent->optlen);

	struct socketoption retrieved = {};
	retrieved.level = sent->level;
	retrieved.optname = sent->optname;
	retrieved.optlen = sent->optlen;
	retrieved.optval = malloc(sent->optlen);
	memset(retrieved.optval, -1, sent->optlen);
	getsockopt(df->sock, retrieved.level, retrieved.optname, retrieved.optval, &retrieved.optlen);
	compare_socketoption(sent, &retrieved);
	free(retrieved.optval);
}

/** Create a socket, assert that this succeeds
 *
 */
void create_socket()
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	g_assert_cmpint(sock, >, 0);
	close(sock);
}

/** Create multiple sockets (IPv4 and UNIX), assert that this succeeds
 *
 */
void create_multiple_sockets()
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	g_assert_cmpint(sock, >, 0);
	int sock2 = socket(AF_INET, SOCK_STREAM, 0);
	int sock3 = socket(AF_UNIX, SOCK_DGRAM, 0);
	g_assert(sock > 0 && sock2 > 0 && sock3 > 0);
	close(sock);
	close(sock2);
	close(sock3);
}

/* Tests start here! */

/** Try to connect a socket
 *
 *  Currently fails due to unknown reasons
 */
void socket_connect(dfixture *df, const void* param)
{
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_flags = AI_PASSIVE, .ai_protocol = 0 };
	struct addrinfo *result = NULL;
	getaddrinfo("www.maunz.org", NULL, &hints, &result);

	struct in_addr *ip_testaddr = malloc(sizeof(struct in_addr));
	inet_aton("127.0.0.1", ip_testaddr);
	uint16_t testport = htons(2342);
	const struct sockaddr_in testaddr = { .sin_family = AF_INET, .sin_port = testport, .sin_addr = *ip_testaddr };
	bind(df->sock, &testaddr, sizeof(testaddr));

	connect(df->sock, (const struct sockaddr*) result, sizeof(result));
}

/** Set three valid socket options: SO_BROADCAST and two intents
 *
 *  Should succeed and be retrievable using getsockopt, values should match
 */
void valid_sockopts(dfixture *df, const void* param)
{
	int flag = 1;
	struct socketoption sock_broadcast = { .level = SOL_SOCKET, .optname = SO_BROADCAST, .optval = &flag, .optlen = sizeof(int) };

	enum category cat = C_KEEPALIVES;
	struct socketoption sock_category = { .level = SOL_INTENTS, .optname = SO_CATEGORY, .optval = &cat, .optlen = sizeof(enum category) };

	int duration = 30;
	struct socketoption sock_duration = { .level = SOL_INTENTS, .optname = SO_DURATION, .optval = &duration, .optlen = sizeof(int) };

	setget_sockopt(df, (const void *) &sock_broadcast);
	setget_sockopt(df, (const void *) &sock_category);
	setget_sockopt(df, (const void *) &sock_duration);
}

/** Set an intent that is semantically incorrect (i.e. does not exist)
 *
 *  Is currently silently accepted
 */
void nonexistent_sockopt(dfixture *df, const void* param)
{
	int flag = 1;
	struct socketoption sock_garbage = { .level = SOL_INTENTS, .optname = 256, .optval = &flag, .optlen = sizeof(int) };

	setget_sockopt(df, (const void *) &sock_garbage);
}

/** Set an intent, then try to retrieve another one
 *
 *  If requested intent does not exist, getsockopt should fail with ENOPROTOOPT
 */
void mismatching_sockopts(dfixture *df, const void* param)
{
	int returned = 0;
	int number = 2342;
	setsockopt(df->sock, SOL_INTENTS, SO_FILESIZE, &number, sizeof(int));
	g_assert_cmpint(returned, ==, 0);

	int number2 = 0;
	socklen_t numbersize = sizeof(int);
	returned = getsockopt(df->sock, SOL_INTENTS, SO_DURATION, &number2, &numbersize);
	g_assert_cmpint(returned, ==, -1);
	g_assert(errno == ENOPROTOOPT);
}

/** Set an intent, then retrieve it with wrong option length
 *
 *  getsockopt should not fail, but silently change option length to the correct
 *  value
 */
void passwronglength_sockopt(dfixture *df, const void* param)
{
	int returned = 0;
	int number = 2342;
	setsockopt(df->sock, SOL_INTENTS, SO_FILESIZE, &number, sizeof(int));
	g_assert_cmpint(returned, ==, 0);

	int number2 = 0;
	socklen_t numbersize = sizeof(double);
	returned = getsockopt(df->sock, SOL_INTENTS, SO_FILESIZE, &number2, &numbersize);
	g_assert_cmpint(returned, ==, 0);
	g_assert_cmpint(numbersize, ==, sizeof(number2));
	g_assert_cmpint(number, ==, number2);
}

/** Set an intent, but pass a NULL buffer as option value
 *
 *  setsockopt should fail with EFAULT
 */
void invalidbuffer_setsockopt(dfixture *df, const void* param)
{
	int *number = NULL;
	int returned = 0;
	returned = setsockopt(df->sock, SOL_INTENTS, SO_FILESIZE, number, sizeof(int));
	g_assert_cmpint(returned, ==, -1);
	g_assert(errno == EFAULT);
}

/** Set an intent, then pass a NULL buffer as option value or length when retrieving
 *
 * getsockopt should fail with EFAULT
 */
void invalidbuffer_getsockopt(dfixture *df, const void* param)
{
	int returned = 0;
	int number = 2342;
	setsockopt(df->sock, SOL_INTENTS, SO_FILESIZE, &number, sizeof(int));
	g_assert_cmpint(returned, ==, 0);

	socklen_t numbersize = sizeof(int);
	returned = getsockopt(df->sock, SOL_INTENTS, SO_FILESIZE, NULL, &numbersize);
	g_assert_cmpint(returned, ==, -1);
	g_assert(errno == EFAULT);

	int number3 = 0;
	returned = getsockopt(df->sock, SOL_INTENTS, SO_FILESIZE, &number3, NULL);
	g_assert_cmpint(returned, ==, -1);
	g_assert(errno == EFAULT);
}

/** Some socket creation and sockopt setting test functions
 *
 * Get a list with the -l option and use --help for more info
 */
int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/socket/create_socket", create_socket);
	g_test_add_func("/socket/create_multiple_sockets", create_multiple_sockets);
	g_test_add("/sockopt/valid", dfixture, NULL, socket_setup, valid_sockopts, socket_close);
	g_test_add("/sockopt/nonexistent", dfixture, NULL, socket_setup, nonexistent_sockopt, socket_close);
	g_test_add("/sockopt/mismatching", dfixture, NULL, socket_setup, nonexistent_sockopt, socket_close);
	g_test_add("/sockopt/passwronglength", dfixture, NULL, socket_setup, passwronglength_sockopt, socket_close);
	g_test_add("/sockopt/invalidbuffer_set", dfixture, NULL, socket_setup, invalidbuffer_setsockopt, socket_close);
	g_test_add("/sockopt/invalidbuffer_get", dfixture, NULL, socket_setup, invalidbuffer_getsockopt, socket_close);
	g_test_add("/socket/socket_connect", dfixture, NULL, socket_setup, socket_connect, socket_close);
	return g_test_run();
}
