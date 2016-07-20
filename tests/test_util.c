/** \file test_util.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
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

#include "clib/muacc.h"
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"

#include "lib/intents.h"
#include "clib/dlog.h"

#include "clib/muacc_client_util.h"

#include "test_util.h"

#ifndef TEST_UTIL_NOISY_DEBUG0
#define TEST_UTIL_NOISY_DEBUG0 0
#endif

#ifndef TEST_UTIL_NOISY_DEBUG1
#define TEST_UTIL_NOISY_DEBUG1 0
#endif

#ifndef TEST_UTIL_NOISY_DEBUG2
#define TEST_UTIL_NOISY_DEBUG2 0
#endif

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

uint32_t deadbeef = 0xdeadbeef;

/** Helper that adds some sockopts to the context
 */
void ctx_add_socketopts(struct _muacc_ctx *ctx, struct socketopt *opts)
{
	if (ctx->sockopts_current == NULL)
	{
		ctx->sockopts_current = _muacc_clone_socketopts(opts);
	}
	else
	{
		struct socketopt *current = ctx->sockopts_current;
		while (current->next != NULL)
		{
			current = current->next;
		}
		current->next = _muacc_clone_socketopts(opts);
	}
}

void ctx_set_category(struct _muacc_ctx *ctx, intent_category_t cat)
{
	struct socketopt *current = ctx->sockopts_current;
	while (current != NULL)
	{
		if (current->level == SOL_INTENTS && current->optname == INTENT_CATEGORY)
		{
			/* Intent category exists - overwrite with new value */
			memcpy(current->optval, &cat, sizeof(enum intent_category));
			break;
		}
		current = current->next;
	}
	if (current == NULL)
	{
		/* Add intent category */
		struct socketopt newopt = { .level = SOL_INTENTS, .optname = INTENT_CATEGORY, .optval=malloc(sizeof(enum intent_category)), .optlen = sizeof(enum intent_category) };
		memcpy(newopt.optval, &cat, sizeof(enum intent_category));
		ctx_add_socketopts(ctx, &newopt);
		free(newopt.optval);
	}
}

void ctx_set_filesize(struct _muacc_ctx *ctx, int filesize)
{
	struct socketopt *current = ctx->sockopts_current;
	while (current != NULL)
	{
		if (current->level == SOL_INTENTS && current->optname == INTENT_FILESIZE)
		{
			/* Intent category exists - overwrite with new value */
			memcpy(current->optval, &filesize, sizeof(int));
			break;
		}
		current = current->next;
	}
	struct socketopt newopt = { .level = SOL_INTENTS, .optname = INTENT_FILESIZE, .optval=malloc(sizeof(int)), .optlen = sizeof(int) };
	memcpy(newopt.optval, &filesize, sizeof(int));
	ctx_add_socketopts(ctx, &newopt);
	free(newopt.optval);
}

/** Helper that compares two lists of sockopts
 *
 *  \return 0 if equal, 1 otherwise
 */
int compare_sockopts(const struct socketopt *a, const struct socketopt *b)
{
	if (a == NULL)
	{
		if (b == NULL) return 0;
		else return 1;
	}
	if (b == NULL)
		return 1;

	while (a != NULL && b != NULL)
	{
		if (a-> level != b->level) return 1;
		g_assert_cmpint(a->level, ==, b->level);
		if (a->optname != b->optname) return 1;
		if (a->optlen != b->optlen) return 1;
		if ( 0 != memcmp(a->optval, b->optval, a->optlen)) return 1;
		a = a->next;
		b = b->next;
	}
	return 0;
}

/** Helper that compares two contexts
 *
 *  \return 0 if equal, 1 otherwise
 */
int compare_contexts(const muacc_context_t *a, const muacc_context_t *b)
{
	if (a->ctx->bind_sa_req_len != b->ctx->bind_sa_req_len) return 1;
	if (a->ctx->bind_sa_suggested_len != b->ctx->bind_sa_suggested_len) return 1;
	if (a->ctx->remote_sa_len != b->ctx->remote_sa_len) return 1;
	if (0 != memcmp(a->ctx->bind_sa_req, b->ctx->bind_sa_req, a->ctx->bind_sa_req_len)) return 1;
	if (0 != memcmp(a->ctx->bind_sa_suggested, b->ctx->bind_sa_suggested, a->ctx->bind_sa_suggested_len)) return 1;
	if (0 != memcmp(a->ctx->remote_sa, b->ctx->remote_sa, a->ctx->remote_sa_len)) return 1;
	if (a->ctx->remote_hostname != NULL && b->ctx->remote_hostname != NULL)
		if(0 != strncmp(a->ctx->remote_hostname, b->ctx->remote_hostname, strlen(a->ctx->remote_hostname+1))) return 1;
	if (a->ctx->remote_addrinfo_hint != NULL && b->ctx->remote_addrinfo_hint != NULL)
		if (0 != memcmp(a->ctx->remote_addrinfo_hint, b->ctx->remote_addrinfo_hint, sizeof(struct addrinfo))) return 1;
	if (a->ctx->remote_addrinfo_res != NULL && b->ctx->remote_addrinfo_res != NULL)
		if (0 != memcmp(a->ctx->remote_addrinfo_res, b->ctx->remote_addrinfo_res, sizeof(struct addrinfo))) return 1;

	if (0 != compare_sockopts(a->ctx->sockopts_current, b->ctx->sockopts_current)) return 1;
	if (0 != compare_sockopts(a->ctx->sockopts_suggested, b->ctx->sockopts_suggested)) return 1;

	return 0;
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
 *
 *  \return 0 if correctly written, 1 otherwise
 */
int compare_tlv(char *buf, size_t buf_pos, size_t buf_len, const void *value, size_t value_len)
{
	const unsigned int *val = value;

	if (buf_pos + value_len > buf_len) return 1;
	DLOG(TEST_UTIL_NOISY_DEBUG2, "Comparing buffer with buf_pos %zd, buf_len %zd, value_len %zd\n", buf_pos, buf_len, value_len);
	for (int i = 0; i < value_len; i++)
	{
		unsigned int mask = *(val + i/4) & (0xff << 8*i);
		DLOG(TEST_UTIL_NOISY_DEBUG2, "%08x %02x %08x %08x\n", (unsigned int) 0xff << 8*i, (unsigned char) buf[buf_pos+i], mask, mask >> 8*i);
		//g_assert_cmphex((unsigned char) buf[buf_pos+i], ==, mask >> 8*i);
		if ((unsigned char) buf[buf_pos+i] != (unsigned char) (mask >> 8*i) ) return 1;
	}
	return 0;
}
