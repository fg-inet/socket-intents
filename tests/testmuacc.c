/** \file testmuacc.c
 *  \brief Set of unit tests for the basic functionality of the muacc client library
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

#ifndef TESTMUACC_NOISY_DEBUG0
#define TESTMUACC_NOISY_DEBUG0 0
#endif

#ifndef TESTMUACC_NOISY_DEBUG1
#define TESTMUACC_NOISY_DEBUG1 0
#endif

#ifndef TESTMUACC_NOISY_DEBUG2
#define TESTMUACC_NOISY_DEBUG2 0
#endif

/** Test that creates a context with a NULL pointer
 *  This should return -1, but not crash the application
 */
void ctx_create_null()
{
	int ret = -2;
	ret = muacc_init_context(NULL);
	g_assert_cmpint(ret, ==, -1);
}

/** Test that prints out a context
 *
 */
void ctx_print(dfixture *df, const void *param)
{
	printf("\n");
	muacc_print_context(df->context);
}

/** Test that copies a context
 *
 */
void ctx_copy(dfixture *df, const void *param)
{
	muacc_context_t *targetctx = malloc(sizeof(muacc_context_t));
	muacc_clone_context(targetctx, df->context);

	if (TESTMUACC_NOISY_DEBUG1) muacc_print_context(targetctx);
	g_assert_cmpint(0, ==, compare_contexts(df->context, targetctx));
}

/** Test that copies a list of sockopts
 *
 */
void sockopts_copy(dfixture *df, const void *param)
{
	struct socketopt *newopt = NULL;
	newopt = _muacc_clone_socketopts((const struct socketopt *) df->context->ctx->sockopts_current);
	g_assert_cmpint(0, ==, compare_sockopts(df->context->ctx->sockopts_current, newopt));
	if (TESTMUACC_NOISY_DEBUG1) _muacc_print_socket_option_list((const struct socketopt *) newopt);
}

/** Test that performs some muacc_ socket calls and tests if socket is writeable
 *
 */
void socketcalls(dfixture *df, const void *param)
{
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

	for (candidate = result; candidate != NULL; candidate = candidate->ai_next) {
		if (muacc_connect(df->context, sfd, candidate->ai_addr, candidate->ai_addrlen) == 0)
			break;
	}
	freeaddrinfo(result);

	if (TESTMUACC_NOISY_DEBUG1) ctx_print(df, NULL);

	/* test if socket is writeable, i.e. we have connected successfully */
	char buf[MUACC_TLV_MAXLEN];
	strncpy(buf, "ohai", 5);
	ret = send(sfd, buf, 5, 0);
	g_assert_cmpint(ret, >, 0);

	ret = muacc_close(df->context, sfd);
	g_assert_cmpint(ret, ==, 0);
}

/** Test that checks if a tag is pushed correctly to the buffer
 *  Buffer should then contain the tag in host byte order,
 *  a length of 0 and no data
 */
void tlv_push_tag()
{
    char buf[MUACC_TLV_MAXLEN];
    size_t writepos = 0;
    size_t buflen = 0;
	size_t readpos = 0;

    muacc_tlv_t label = 0x12345678;
	size_t valuelen = 0;

    DLOG(TESTMUACC_NOISY_DEBUG2, "Pushing label %x of length %zd\n", (unsigned int) label, sizeof(muacc_tlv_t));

    buflen = _muacc_push_tlv_tag(buf, &writepos, sizeof(buf), label);

    if (TESTMUACC_NOISY_DEBUG2) tlv_print_buffer(buf, buflen);
    g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &label, sizeof(muacc_tlv_t)));
	readpos += sizeof(muacc_tlv_t);
	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &valuelen, sizeof(size_t)));
}

/** Test that checks if a value is pushed correctly to the buffer
 *  Buffer should then contain the tag, the length of the value 
 *  and the value itself in host byte order
 */
void tlv_push_value()
{
    char buf[MUACC_TLV_MAXLEN];
    size_t writepos = 0;
    size_t buflen = 0;
	size_t readpos = 0;

	muacc_tlv_t label = action;
    muacc_mam_action_t reason = 0xcaffe007;
	size_t valuelen = sizeof(muacc_mam_action_t);

    DLOG(TESTMUACC_NOISY_DEBUG2, "Pushing label %x value %x length %x\n", (unsigned int) action, (unsigned int) reason, (unsigned int) sizeof(muacc_mam_action_t));

    buflen = _muacc_push_tlv(buf, &writepos, sizeof(buf), label, &reason, sizeof(muacc_mam_action_t));

    if (TESTMUACC_NOISY_DEBUG2) tlv_print_buffer(buf, buflen);

	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &label, sizeof(muacc_tlv_t)));
	readpos += sizeof(muacc_tlv_t);
	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &valuelen, sizeof(size_t)));
	readpos += sizeof(size_t);
	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &reason, sizeof(muacc_mam_action_t)));

}

/** Test that checks if a hostname is pushed correctly to the buffer 
 */
void tlv_push_hostname()
{
    char buf[MUACC_TLV_MAXLEN];
    size_t writepos = 0;
    size_t buflen = 0;
	size_t readpos = 0;

	muacc_tlv_t label = remote_hostname;
	char *hostname;
	asprintf(&hostname, "www.maunz.org");
	size_t valuelen = strlen(hostname)+1;

    DLOG(TESTMUACC_NOISY_DEBUG2, "Pushing label %x value %s length %x\n", (unsigned int) action, hostname, valuelen);

    buflen = _muacc_push_tlv(buf, &writepos, sizeof(buf), label, hostname, valuelen);

    if (TESTMUACC_NOISY_DEBUG2) tlv_print_buffer(buf, buflen);

	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &label, sizeof(muacc_tlv_t)));
	readpos += sizeof(muacc_tlv_t);
	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &valuelen, sizeof(size_t)));
	readpos += sizeof(size_t);
	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) hostname, valuelen));

}

/** Test that checks if a list of socketopts is pushed correctly to the buffer
 */
void tlv_push_socketopt(dfixture *df, const void* param)
{
	char *buf;
    size_t writepos = 0;
	size_t readpos = 0;
    size_t buflen = 0;
	size_t valuelen = 0;
	
	
	muacc_tlv_t label = sockopts_current;

	buflen = _muacc_push_socketopt_tlv(df->tlv_buffer, &writepos, df->tlv_buffer_len, label, df->context->ctx->sockopts_current);
	valuelen = writepos - sizeof(muacc_tlv_t) - sizeof(size_t);
	buf = df->tlv_buffer;
	

	if (TESTMUACC_NOISY_DEBUG2)
	{
		printf("buflen = %zd, valuelen = %zd [hex: %08zx]\n", buflen, valuelen, valuelen);
		_muacc_print_socket_option_list((const struct socketopt *) df->context->ctx->sockopts_current);
		tlv_print_buffer(buf, buflen);
	}

	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &label, sizeof(muacc_tlv_t)));
	readpos += sizeof(muacc_tlv_t);
	g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) &valuelen, sizeof(size_t)));
	readpos += sizeof(size_t);

	struct socketopt *current = df->context->ctx->sockopts_current;
	while (current != NULL)
	{
		g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) current, sizeof(struct socketopt)));
		readpos += sizeof(struct socketopt);
		g_assert_cmpint(0, ==, compare_tlv(buf, readpos, buflen, (const void *) current->optval, current->optlen));
		readpos += current->optlen;
		current = current->next;
	}

}

/** Test that checks if socket opts are packed and unpacked correctly i.e. without changing the content */
void tlv_unpack_socketopt(dfixture *df, const void* param)
{
	struct socketopt *newopt;

    size_t writepos = 0;
	size_t readpos = 0;
	size_t valuelen = 0;
	
	
	muacc_tlv_t label = sockopts_current;

	if (TESTMUACC_NOISY_DEBUG2)
		_muacc_print_socket_option_list(df->context->ctx->sockopts_current);

	_muacc_push_socketopt_tlv(df->tlv_buffer, &writepos, df->tlv_buffer_len, label, df->context->ctx->sockopts_current);
	valuelen = writepos - sizeof(muacc_tlv_t) - sizeof(size_t);
	
	readpos = sizeof(muacc_tlv_t) + sizeof(size_t);
	_muacc_extract_socketopt_tlv((df->tlv_buffer)+readpos, valuelen, &newopt);
	
	g_assert_cmpint(0, ==, compare_sockopts(df->context->ctx->sockopts_current, newopt));
	if (TESTMUACC_NOISY_DEBUG2)
		_muacc_print_socket_option_list((const struct socketopt *) newopt);
}




/** Add test cases to the test harness */
int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	DLOG(TESTMUACC_NOISY_DEBUG0, "Welcome to the muacc testing functions\n");
	printf("================================================\n");
	// g_test_add("/ctx/print_empty", dfixture, NULL, ctx_empty_setup, ctx_print, ctx_destroy);
	g_test_add("/ctx/print_data", dfixture, NULL, ctx_data_setup, ctx_print, ctx_destroy);
	g_test_add("/ctx/copy_ctx", dfixture, NULL, ctx_empty_setup, ctx_copy, ctx_destroy);
	g_test_add_func("/ctx/create_null", ctx_create_null);
	g_test_add("/ctx/socketcalls", dfixture, NULL, ctx_empty_setup, socketcalls, ctx_destroy);
	g_test_add("/sockopts/copy_data", dfixture, NULL, ctx_data_setup, sockopts_copy, ctx_destroy);
	g_test_add("/sockopts/copy_empty", dfixture, NULL, ctx_empty_setup, sockopts_copy, ctx_destroy);
	g_test_add_func("/tlv/push_value", tlv_push_value);
	g_test_add_func("/tlv/push_tag", tlv_push_tag);
	g_test_add_func("/tlv/push_hostname", tlv_push_hostname);
	g_test_add("/tlv/push_socketopt", dfixture, NULL, ctx_data_tlv_empty_setup, tlv_push_socketopt, ctx_tlv_destroy);
	// g_test_add("/tlv/push_socketopt/evulshortbuf", dfixture, NULL, ctx_data_tlv_evilshort_setup, tlv_push_socketopt, ctx_tlv_destroy);
	g_test_add("/tlv/unpack_socketopt", dfixture, NULL, ctx_data_tlv_empty_setup, tlv_unpack_socketopt, ctx_tlv_destroy);
	return g_test_run();
}
