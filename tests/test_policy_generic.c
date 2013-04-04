/** \file test_policy_sample.c
 *  \brief Set of unit tests for muacc client and multi access manager with "sample policy"
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include "../clib/muacc.h"
#include "../clib/muacc_ctx.h"
#include "../clib/muacc_tlv.h"
#include "../clib/muacc_util.h"
#include "../libintents/libintents.h"
#include "../clib/dlog.h"
#include "test_util.h"

#ifndef TEST_POLICY_SAMPLE_NOISY_DEBUG0
#define TEST_POLICY_SAMPLE_NOISY_DEBUG0 1
#endif

#ifndef TEST_POLICY_SAMPLE_NOISY_DEBUG1
#define TEST_POLICY_SAMPLE_NOISY_DEBUG1 1
#endif

#ifndef TEST_POLICY_SAMPLE_NOISY_DEBUG2
#define TEST_POLICY_SAMPLE_NOISY_DEBUG2 1
#endif

/** Data structure that contains all relevant data for a getaddrinfo request
 *  To be supplied to the getaddrinfo_request test function as a parameter
 */
struct addrinfo_context
{
	char *node;
	char *service;
	struct addrinfo *hints;
};

/** Helper that creates an addrinfo context for a request for localhost and a given port
 */
struct addrinfo_context *create_actx_localport (int port)
{
	struct addrinfo_context *actx = malloc(sizeof(struct addrinfo_context));
	memset(actx, 0, sizeof(struct addrinfo_context));

	actx->hints = malloc(sizeof(struct addrinfo));
	memset(actx->hints, 0, sizeof(struct addrinfo));

	actx->hints->ai_family = AF_UNSPEC;
	actx->hints->ai_socktype = SOCK_DGRAM;
	actx->hints->ai_flags = AI_PASSIVE;

	asprintf(&actx->service, "%d", port);

	return actx;
}

/** Helper that creates an addrinfo context for a remote host and, optionally, port
 */
struct addrinfo_context *create_actx_remote (int port, const char *name)
{
	struct addrinfo_context *actx = malloc(sizeof(struct addrinfo_context));
	memset(actx, 0, sizeof(struct addrinfo_context));

	actx->hints = malloc(sizeof(struct addrinfo));
	memset(actx->hints, 0, sizeof(struct addrinfo));

	actx->hints->ai_family = AF_UNSPEC;
	actx->hints->ai_socktype = SOCK_DGRAM;

	if (name != NULL)
	{
		asprintf(&actx->node, "%s", name);
	}
	else
	{
		return NULL;
	}

	if (port != 0)
	{
		asprintf(&actx->service, "%d", port);
	}

	return actx;
}

/** Data structure that contains all relevant data for socket creation and a connect request
 *  To be supplied to the connect_request test function as a parameter
 */ 
struct connect_context
{
	int family;
	int socktype;
	int protocol;
	struct sockaddr *remote_addr;
	socklen_t remote_addr_len;
};

/** Helper that creates a connect context to a remote server
 */
struct connect_context *create_cctx_remote(int family, int socktype, int protocol, int port, const char *hostname)
{
	struct connect_context *cctx = malloc(sizeof(struct connect_context));
	memset(cctx, 0, sizeof(struct connect_context));

	cctx->family = family;
	cctx->socktype = socktype;
	cctx->protocol = protocol;

	struct addrinfo_context *actx = create_actx_remote(port, hostname);
	actx->hints->ai_family = family;
	actx->hints->ai_socktype = socktype;
	actx->hints->ai_protocol = protocol;

	struct addrinfo *result = NULL;

	int ret = getaddrinfo(actx->node, actx->service, actx->hints, &result);
	g_assert_cmpint(ret, ==, 0);
	g_assert(result != NULL);

	cctx->remote_addr_len = result->ai_addrlen;
	cctx->remote_addr = _muacc_clone_sockaddr(result->ai_addr, result->ai_addrlen);
	freeaddrinfo(result);

	return cctx;
}

/** Test that sends a getaddrinfo resolve request to the MAM and prints the context before and after
 */
void getaddrinfo_request(dfixture *df, const void *param)
{
	const struct addrinfo_context *actx = (const struct addrinfo_context *) param;
	if (actx == NULL) return;

	struct addrinfo *result = NULL;

	printf("Before getaddrinfo: \n");
	muacc_print_context(df->context);

	muacc_getaddrinfo(df->context, actx->node, actx->service, actx->hints, &result);

	printf("After getaddrinfo: \n");
	muacc_print_context(df->context);
}

/** Test that creates a socket, sends a connect resolve request to the MAM and prints the context before and after
 */
void connect_request(dfixture *df, const void *param)
{
	const struct connect_context *cctx = (const struct connect_context *) param;
	if (cctx == NULL) return;

	int sfd = muacc_socket(df->context, cctx->family, cctx->socktype, cctx->protocol);
	g_assert_cmpint(sfd, >, 0);

	printf("Before connect: \n");
	muacc_print_context(df->context);

	int ret = muacc_connect(df->context, sfd, cctx->remote_addr, cctx->remote_addr_len);
	g_assert_cmpint(ret, ==, 0);

	printf("After connect: \n");
	muacc_print_context(df->context);
}

/** Add test cases to the test harness */
int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	DLOG(TEST_POLICY_SAMPLE_NOISY_DEBUG0, "Welcome to the muacc testing functions\n");
	printf("================================================\n");
	g_test_add("/ctx/getaddrinfo_localport", dfixture, create_actx_localport(1338), ctx_empty_setup, getaddrinfo_request, ctx_destroy);
	g_test_add("/ctx/getaddrinfo_remote", dfixture, create_actx_remote(1337, "www.maunz.org"), ctx_empty_setup, getaddrinfo_request, ctx_destroy);
	g_test_add("/ctx/connect_remote_v4_google", dfixture, create_cctx_remote(AF_INET, SOCK_STREAM, 0, 80, "www.google.com"), ctx_empty_setup, connect_request, ctx_destroy);
	return g_test_run();
}
