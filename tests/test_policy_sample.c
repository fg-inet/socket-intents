/** \file test_policy_sample.c
 *  \brief Set of unit tests for muacc client and multi access manager with "sample policy"
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
#include "../clib/muacc.h"
#include "../clib/muacc_ctx.h"
#include "../clib/muacc_tlv.h"
#include "../clib/muacc_util.h"
#include "../libintents/libintents.h"
#include "../clib/dlog.h"
#include "test_util.h"

#ifndef TEST_POLICY_SAMPLE_NOISY_DEBUG0
#define TEST_POLICY_SAMPLE_NOISY_DEBUG0 0
#endif

#ifndef TEST_POLICY_SAMPLE_NOISY_DEBUG1
#define TEST_POLICY_SAMPLE_NOISY_DEBUG1 0
#endif

#ifndef TEST_POLICY_SAMPLE_NOISY_DEBUG2
#define TEST_POLICY_SAMPLE_NOISY_DEBUG2 0
#endif

/** Test that performs some muacc_ socket calls and checks if the context changes (it shouldn't)
 *
 */
void socketcalls(dfixture *df, const void *param)
{
	ctx_add_socketopts(df->context->ctx);

	muacc_context_t *origctx = malloc(sizeof(muacc_context_t));
	muacc_clone_context(origctx, df->context);

	struct addrinfo *hints = malloc(sizeof(struct addrinfo));
	memset(hints, 0, sizeof(struct addrinfo));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_DGRAM;
	hints->ai_flags = AI_PASSIVE;
	hints->ai_protocol = 0;

	struct addrinfo *result = NULL;
	struct addrinfo *candidate = NULL;
	int ret = -2;
	int sfd;

	ret = muacc_getaddrinfo(df->context, NULL, "1338", hints, &result);
	g_assert_cmpint(ret, ==, 0);
	g_assert(result != NULL);
	g_assert_cmpint(compare_contexts(df->context, origctx), ==, 0);

	for (candidate = result; candidate != NULL; candidate = candidate->ai_next) {
		printf("trying out\n");
		sfd = muacc_socket(df->context, candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
		if (sfd == -1)
			continue;
		if (muacc_bind(df->context, sfd, candidate->ai_addr, candidate->ai_addrlen) == 0)
			break;

		close (sfd);
	}

	g_assert_cmpint(sfd, >, 0);

	hints->ai_flags = 0;
	result = NULL;

	ret = muacc_getaddrinfo(df->context, "www.maunz.org", "1337", hints, &result);
	g_assert_cmpint(ret, ==, 0);
	g_assert(result != NULL);

	muacc_release_context(origctx);
	muacc_clone_context(origctx, df->context);
	for (candidate = result; candidate != NULL; candidate = candidate->ai_next) {
		if (muacc_connect(df->context, sfd, candidate->ai_addr, candidate->ai_addrlen) == 0)
			break;
	}
	g_assert_cmpint(compare_contexts(df->context, origctx), ==, 0);
	freeaddrinfo(result);

	if (TEST_POLICY_SAMPLE_NOISY_DEBUG1)
	{
		printf("\n");
		muacc_print_context(df->context);
	}
}

/** Add test cases to the test harness */
int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	DLOG(TEST_POLICY_SAMPLE_NOISY_DEBUG0, "Welcome to the muacc testing functions\n");
	printf("================================================\n");
	g_test_add("/ctx/socketcalls", dfixture, NULL, ctx_empty_setup, socketcalls, ctx_destroy);
	return g_test_run();
}
