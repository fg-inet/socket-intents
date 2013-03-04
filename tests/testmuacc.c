/** \file testmuacc.c
 *  \brief Set of unit tests for the muacc library
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

#ifndef memset_pattern4
void memset_pattern4 (void *dst, const void *pat, size_t len)
{
 	char *pos = (char *) dst;
	while(len > 0){
		memcpy(pos, pat, len>4?4:len);
		pos+=4; len -=4;
	} 
}
#endif

#ifndef TESTMUACC_NOISY_DEBUG
#define TESTMUACC_NOISY_DEBUG 0
#endif

/** Fixture = Element used in a set of tests
 *
 */
typedef struct
{
	muacc_context_t *context;
	char *tlv_buffer;
	size_t tlv_buffer_len;
} dfixture;

uint32_t deadbeef = 0xdeadbeef;

/** Helper that creates an empty muacc context
 *
 */
void ctx_empty_setup(dfixture *df, const void *test_data)
{
	DLOG(TESTMUACC_NOISY_DEBUG, "\n===========\n");
	muacc_context_t *newctx = malloc(sizeof(muacc_context_t));
	df->context = newctx;
	muacc_init_context(df->context);
}

/** Helper that creates a muacc context and fills it
 *  with some data
 */
void ctx_data_setup(dfixture *df, const void *test_data)
{
	DLOG(TESTMUACC_NOISY_DEBUG, "\n===========\n");
	muacc_context_t *newctx = malloc(sizeof(muacc_context_t));
	df->context = newctx;
	muacc_init_context(df->context);

	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_flags = AI_PASSIVE };
	df->context->ctx->remote_addrinfo_hint = malloc(sizeof(struct addrinfo));
	memcpy(df->context->ctx->remote_addrinfo_hint, &hints, sizeof(struct addrinfo));

	struct addrinfo *result1 = malloc(sizeof(struct addrinfo));
	if (getaddrinfo("www.maunz.org", NULL, &hints, &result1) != 0)
	{
		printf("Getaddrinfo failed: %s \n", gai_strerror(errno));
	}
	else
	{
		df->context->ctx->remote_addrinfo_res = result1;
	}

	struct socketopt testopt = { .level = SOL_SOCKET, .optname = SO_BROADCAST, .optval=malloc(sizeof(int)), .optlen = sizeof(int) };
	int flag = 1;
	memcpy(testopt.optval, &flag, sizeof(int));

	df->context->ctx->sockopts_current = malloc(sizeof(struct socketopt));
	memcpy(df->context->ctx->sockopts_current, &testopt, sizeof(struct socketopt));

	struct socketopt testopt2 = { .level = SOL_INTENTS, .optname = SO_CATEGORY, .optval=malloc(sizeof(enum category)), .optlen = sizeof(enum category) };
	enum category cat = C_KEEPALIVES;
	memcpy(testopt2.optval, &cat, sizeof(enum category));

	df->context->ctx->sockopts_current->next = malloc(sizeof(struct socketopt));
	memcpy(df->context->ctx->sockopts_current->next, &testopt2, sizeof(struct socketopt));
}

/** Helper that releases a context
 *
 */
void ctx_destroy(dfixture *df, const void *test_data)
{
	muacc_release_context(df->context);
	free(df->context);
	DLOG(TESTMUACC_NOISY_DEBUG, "\n===========\n");
}

/** Helper that creates a large tlv buffer with test pattern
 *
 */
void tlv_empty_setup(dfixture *df, const void *test_data)
{
	DLOG(TESTMUACC_NOISY_DEBUG, "\n===========\n");
	df->tlv_buffer_len = MUACC_TLV_MAXLEN;
	df->tlv_buffer = malloc(df->tlv_buffer_len);
	DLOG(TESTMUACC_NOISY_DEBUG, "allocated %zd bytes for df->tlv_buffer - got buffer at %p\n", df->tlv_buffer_len, df->tlv_buffer);
	memset_pattern4(df->tlv_buffer, &deadbeef, df->tlv_buffer_len);
}

/** Helper that creates a damn small tlv buffer with test pattern
 *
 */
void tlv_evilshort_setup(dfixture *df, const void *test_data)
{
	DLOG(TESTMUACC_NOISY_DEBUG, "\n===========\n");
	df->tlv_buffer_len = sizeof(muacc_tlv_t)+sizeof(size_t)+1;
	df->tlv_buffer = malloc(df->tlv_buffer_len);
	DLOG(TESTMUACC_NOISY_DEBUG, "allocated %zd bytes for df->tlv_buffer - got buffer at %p\n", df->tlv_buffer_len, df->tlv_buffer);
	memset_pattern4(df->tlv_buffer, &deadbeef, df->tlv_buffer_len);
}


/** Helper that releases a the tlv buffer
 *
 */
void tlv_destroy(dfixture *df, const void *test_data)
{
	muacc_release_context(df->context);
	free(df->tlv_buffer);
	df->tlv_buffer = NULL;
	df->tlv_buffer_len = 0;
	DLOG(TESTMUACC_NOISY_DEBUG, "\n===========\n");
}

void ctx_data_tlv_evilshort_setup(dfixture *df, const void* param)
{
	ctx_data_setup(df, param);
	tlv_evilshort_setup(df, param);
}

void ctx_data_tlv_empty_setup(dfixture *df, const void* param)
{
	ctx_data_setup(df, param);
	tlv_empty_setup(df, param);
}

void ctx_tlv_destroy(dfixture *df, const void* param)
{
	tlv_destroy(df, param);
	ctx_destroy(df, param);
}

/** Helper that compares two lists of sockopts
 *
 */
void compare_sockopts(const struct socketopt *a, const struct socketopt *b)
{
	while (a != NULL && b != NULL)
	{
		g_assert_cmpint(a->level, ==, b->level);
		g_assert_cmpint(a->optname, ==, b->optname);
		g_assert_cmpint(a->optlen, ==, b->optlen);
		g_assert( 0 == memcmp(a->optval, b->optval, a->optlen));
		a = a->next;
		b = b->next;
	}
}

/** Helper that compares two contexts
 *
 */
void compare_contexts(const muacc_context_t *a, const muacc_context_t *b)
{
	g_assert_cmpint(a->ctx->bind_sa_req_len, ==, b->ctx->bind_sa_req_len);
	g_assert_cmpint(a->ctx->bind_sa_suggested_len, ==, b->ctx->bind_sa_suggested_len);
	g_assert_cmpint(a->ctx->remote_sa_len, ==, b->ctx->remote_sa_len);
	g_assert(0 == memcmp(a->ctx->bind_sa_req, b->ctx->bind_sa_req, a->ctx->bind_sa_req_len));
	g_assert(0 == memcmp(a->ctx->bind_sa_suggested, b->ctx->bind_sa_suggested, a->ctx->bind_sa_suggested_len));
	g_assert(0 == memcmp(a->ctx->remote_sa, b->ctx->remote_sa, a->ctx->remote_sa_len));
	g_assert_cmpstr(a->ctx->remote_hostname, ==, b->ctx->remote_hostname);
	if (a->ctx->remote_addrinfo_hint != NULL)
		g_assert(0 == memcmp(a->ctx->remote_addrinfo_hint, b->ctx->remote_addrinfo_hint, sizeof(struct addrinfo)));
	if (a->ctx->remote_addrinfo_res != NULL)
		g_assert(0 == memcmp(a->ctx->remote_addrinfo_res, b->ctx->remote_addrinfo_res, sizeof(struct addrinfo)));

	compare_sockopts(a->ctx->sockopts_current, b->ctx->sockopts_current);
	compare_sockopts(a->ctx->sockopts_suggested, b->ctx->sockopts_suggested);
}

/** Helper to print out the TLV buffer
 *  (Host byte order -> LSB first on many systems!)
 */
void tlv_print_buffer(char buf[], size_t buflen)
{
    printf("TLV buffer: ");
    for (int i = 0; i < buflen; i++)
    {
        printf("%02x ", (unsigned char) buf[i]);
    }
    printf("length %d \n", (int) buflen);
}

/** Compare tlv buffer with a value that was supposed to be written into it
 *  in host byte order
 */
void compare_tlv(char *buf, size_t buf_pos, size_t buf_len, const void *value, size_t value_len)
{
	const unsigned int *val = value;

	g_assert(buf_pos + value_len <= buf_len);
	DLOG(TESTMUACC_NOISY_DEBUG, "Comparing buffer with buf_pos %zd, buf_len %zd, value_len %zd\n", buf_pos, buf_len, value_len);
	for (int i = 0; i < value_len; i++)
	{
		unsigned int mask = *(val + i/4) & (0xff << 8*i);
		DLOG(TESTMUACC_NOISY_DEBUG, "%08x %02x %08x %08x\n", (unsigned int) 0xff << 8*i, (unsigned char) buf[buf_pos+i], mask, mask >> 8*i);
		g_assert_cmphex((unsigned char) buf[buf_pos+i], ==, mask >> 8*i);
	}
}

/** Trying to create a context with a NULL pointer
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

	if (TESTMUACC_NOISY_DEBUG) muacc_print_context(targetctx);
	compare_contexts(df->context, targetctx);
}

/** Test that copies a list of sockopts
 *
 */
void sockopts_copy(dfixture *df, const void *param)
{
	struct socketopt *newopt = NULL;
	newopt = _muacc_clone_socketopts((const struct socketopt *) df->context->ctx->sockopts_current);
	compare_sockopts(df->context->ctx->sockopts_current, newopt);
	if (TESTMUACC_NOISY_DEBUG) _muacc_print_socket_option_list((const struct socketopt *) newopt);
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

    DLOG(TESTMUACC_NOISY_DEBUG, "Pushing label %x of length %zd\n", (unsigned int) label, sizeof(muacc_tlv_t));

    buflen = _muacc_push_tlv_tag(buf, &writepos, sizeof(buf), label);

    if (TESTMUACC_NOISY_DEBUG) tlv_print_buffer(buf, buflen);
    compare_tlv(buf, readpos, buflen, (const void *) &label, sizeof(muacc_tlv_t));
	readpos += sizeof(muacc_tlv_t);
	compare_tlv(buf, readpos, buflen, (const void *) &valuelen, sizeof(size_t));
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

    DLOG(TESTMUACC_NOISY_DEBUG, "Pushing label %x value %x length %x\n", (unsigned int) action, (unsigned int) reason, (unsigned int) sizeof(muacc_mam_action_t));

    buflen = _muacc_push_tlv(buf, &writepos, sizeof(buf), label, &reason, sizeof(muacc_mam_action_t));

    if (TESTMUACC_NOISY_DEBUG) tlv_print_buffer(buf, buflen);

	compare_tlv(buf, readpos, buflen, (const void *) &label, sizeof(muacc_tlv_t));
	readpos += sizeof(muacc_tlv_t);
	compare_tlv(buf, readpos, buflen, (const void *) &valuelen, sizeof(size_t));
	readpos += sizeof(size_t);
	compare_tlv(buf, readpos, buflen, (const void *) &reason, sizeof(muacc_mam_action_t));

}

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
	

	if (TESTMUACC_NOISY_DEBUG)
	{
		printf("buflen = %zd, valuelen = %zd [hex: %08zx]\n", buflen, valuelen, valuelen);
		_muacc_print_socket_option_list((const struct socketopt *) df->context->ctx->sockopts_current);
		tlv_print_buffer(buf, buflen);
	}

	compare_tlv(buf, readpos, buflen, (const void *) &label, sizeof(muacc_tlv_t));
	readpos += sizeof(muacc_tlv_t);
	compare_tlv(buf, readpos, buflen, (const void *) &valuelen, sizeof(size_t));
	readpos += sizeof(size_t);

	struct socketopt *current = df->context->ctx->sockopts_current;
	while (current != NULL)
	{
		compare_tlv(buf, readpos, buflen, (const void *) current, sizeof(struct socketopt));
		readpos += sizeof(struct socketopt);
		compare_tlv(buf, readpos, buflen, (const void *) current->optval, current->optlen);
		readpos += current->optlen;
		current = current->next;
	}

}

void tlv_unpack_socketopt(dfixture *df, const void* param)
{
	struct socketopt *newopt;

	char *buf;
    size_t writepos = 0;
	size_t readpos = 0;
    size_t buflen = 0;
	size_t valuelen = 0;
	
	
	muacc_tlv_t label = sockopts_current;

	if (TESTMUACC_NOISY_DEBUG) 
		_muacc_print_socket_option_list(df->context->ctx->sockopts_current);

	buflen = _muacc_push_socketopt_tlv(df->tlv_buffer, &writepos, df->tlv_buffer_len, label, df->context->ctx->sockopts_current);
	valuelen = writepos - sizeof(muacc_tlv_t) - sizeof(size_t);
	
	readpos = sizeof(muacc_tlv_t) + sizeof(size_t);
	_muacc_extract_socketopt_tlv((df->tlv_buffer)+readpos, valuelen, &newopt);
	
	compare_sockopts(df->context->ctx->sockopts_current, newopt);
	if (TESTMUACC_NOISY_DEBUG) 
		_muacc_print_socket_option_list((const struct socketopt *) newopt);
}




/** Add test cases to the test harness */
int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	DLOG(TESTMUACC_NOISY_DEBUG, "Welcome to the muacc testing functions\n");
	printf("================================================\n");
	// g_test_add("/ctx/print_empty", dfixture, NULL, ctx_empty_setup, ctx_print, ctx_destroy);
	g_test_add("/ctx/print_data", dfixture, NULL, ctx_data_setup, ctx_print, ctx_destroy);
	g_test_add("/ctx/copy_ctx", dfixture, NULL, ctx_empty_setup, ctx_copy, ctx_destroy);
	g_test_add_func("/ctx/create_null", ctx_create_null);
	g_test_add("/sockopts/copy_data", dfixture, NULL, ctx_data_setup, sockopts_copy, ctx_destroy);
	g_test_add("/sockopts/copy_empty", dfixture, NULL, ctx_empty_setup, sockopts_copy, ctx_destroy);
	g_test_add_func("/tlv/push_value", tlv_push_value);
	g_test_add_func("/tlv/push_tag", tlv_push_tag);
	g_test_add("/tlv/push_socketopt", dfixture, NULL, ctx_data_tlv_empty_setup, tlv_push_socketopt, ctx_tlv_destroy);
	// g_test_add("/tlv/push_socketopt/evulshortbuf", dfixture, NULL, ctx_data_tlv_evilshort_setup, tlv_push_socketopt, ctx_tlv_destroy);
	g_test_add("/tlv/unpack_socketopt", dfixture, NULL, ctx_data_tlv_empty_setup, tlv_unpack_socketopt, ctx_tlv_destroy);
	return g_test_run();
}
