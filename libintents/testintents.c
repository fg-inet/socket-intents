/* 
 * Application to test the Intents socket library extension
 * Run with LD_PRELOAD=./libintents.so.1.0 ./testintents
 * 
 * Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "libintents.h"

typedef struct
{
	int sock;
} dfixture;

struct socketoption
{
	int level;
	int optname;
	void *optval;
	socklen_t optlen;
};

void compare_socketoption(const struct socketoption *a, const struct socketoption *b)
{
	printf("=== Comparing socketoptions ===\n");
	g_assert_cmpint((int) a->optlen, ==, (int) b->optlen);
	g_assert( 0 == memcmp(a->optval, b->optval, a->optlen));
}

void create_socket()
{
	printf("\n=== Create and destroy socket ===\n");
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	g_assert_cmpint(sock, >, 0);
	printf("=== Successfully created socket %d. ===\n", sock);
	close(sock);
}

void create_multiple_sockets()
{
	printf("\n=== Create and destroy 3 sockets ===\n");
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	g_assert_cmpint(sock, >, 0);
	int sock2 = socket(AF_INET, SOCK_STREAM, 0);
	int sock3 = socket(AF_UNIX, SOCK_DGRAM, 0);
	g_assert(sock > 0 && sock2 > 0 && sock3 > 0);
	printf("=== Successfully created sockets %d, %d and %d. ===\n", sock, sock2, sock3);
	close(sock);
	close(sock2);
	close(sock3);
}

void socket_setup(dfixture *df, const void *test_data)
{
	printf("\n===========\n");
	df->sock = socket(AF_INET, SOCK_DGRAM, 0);
}

void socket_close(dfixture *df, const void * test_data)
{
	close(df->sock);
	printf("\n===========\n");
}

void setget_sockopt(dfixture *df, const void* param)
{
	printf("=== Setsockopt ===\n");
	const struct socketoption *sent = param;
	setsockopt(df->sock, sent->level, sent->optname, sent->optval, sent->optlen);
	struct socketoption retrieved = {};
	retrieved.level = sent->level;
	retrieved.optname = sent->optname;
	retrieved.optlen = sent->optlen;
	retrieved.optval = malloc(sent->optlen);
	memset(retrieved.optval, -1, sent->optlen);
	printf("=== Getsockopt ===\n");
	getsockopt(df->sock, retrieved.level, retrieved.optname, retrieved.optval, &retrieved.optlen);
	compare_socketoption(sent, &retrieved);
	free(retrieved.optval);
}

void socket_connect(dfixture *df, const void* param)
{
	printf("=== Getaddrinfo ===\n");
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_flags = AI_PASSIVE, .ai_protocol = 0 };
	struct addrinfo *result = NULL;
	getaddrinfo("www.maunz.org", NULL, &hints, &result);

	printf("=== Bind ===\n");
	struct in_addr *ip_testaddr = malloc(sizeof(struct in_addr));
	inet_aton("127.0.0.1", ip_testaddr);
	uint16_t testport = htons(2342);
	const struct sockaddr_in testaddr = { .sin_family = AF_INET, .sin_port = testport, .sin_addr = *ip_testaddr };
	bind(df->sock, &testaddr, sizeof(testaddr));

	printf("=== Connect ===\n");
	connect(df->sock, (const struct sockaddr*) result, sizeof(result));
}

int main(int argc, char *argv[])
	/* 
	 * Create a socket and set some options
	 */
{
	struct socketoption sock_broadcast = { .level=SOL_SOCKET, .optname=SO_BROADCAST, .optval=malloc(sizeof(int)), .optlen=sizeof(int) };
	int flag = 1;
	sock_broadcast.optval = &flag;

	struct socketoption sock_category = { .level=SOL_INTENTS, .optname=SO_CATEGORY, .optval=malloc(sizeof(enum category)), .optlen=sizeof(enum category) };
	int cat = C_KEEPALIVES;
	sock_category.optval = &cat;

	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/socket/create_socket", create_socket);
	g_test_add_func("/socket/create_multiple_sockets", create_multiple_sockets);
	g_test_add("/socket/setget_sockopt", dfixture, (const void *) &sock_category, socket_setup, setget_sockopt, socket_close);
	g_test_add("/socket/setget_sockopt", dfixture, (const void *) &sock_broadcast, socket_setup, setget_sockopt, socket_close);
	g_test_add("/socket/socket_connect", dfixture, NULL, socket_setup, socket_connect, socket_close);
	return g_test_run();
}
