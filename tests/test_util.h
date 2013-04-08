/** \file test_util.h
 *	\brief Set of helpers for various test programs
 */

#ifndef __TEST_UTIL_H__
#define __TEST_UTIL_H__

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
#include "../clib/muacc_types.h"
#include "../clib/muacc_ctx.h"
#include "../clib/muacc_tlv.h"
#include "../clib/muacc_util.h"
#include "../libintents/libintents.h"
#include "../clib/dlog.h"

#ifndef memset_pattern4
void memset_pattern4 (void *dst, const void *pat, size_t len);
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

/** Helper that creates an empty muacc context
 *
 */
void ctx_empty_setup(dfixture *df, const void *test_data);

/** Helper that adds some sockopts to the context
 */
void ctx_add_socketopts(struct _muacc_ctx *ctx, struct socketopt *opts);

/** Helper that creates a muacc context and fills it
 *  with some data
 */
void ctx_data_setup(dfixture *df, const void *test_data);

/** Helper that releases a context
 *
 */
void ctx_destroy(dfixture *df, const void *test_data);

/** Helper that creates a large tlv buffer with test pattern
 *
 */
void tlv_empty_setup(dfixture *df, const void *test_data);

/** Helper that creates a damn small tlv buffer with test pattern
 *
 */
void tlv_evilshort_setup(dfixture *df, const void *test_data);

/** Helper that releases a the tlv buffer
 *
 */
void tlv_destroy(dfixture *df, const void *test_data);

void ctx_data_tlv_evilshort_setup(dfixture *df, const void* param);

void ctx_data_tlv_empty_setup(dfixture *df, const void* param);

void ctx_tlv_destroy(dfixture *df, const void* param);

/** Helper that compares two lists of sockopts
 *
 *  \return 0 if equal, 1 otherwise
 */
int compare_sockopts(const struct socketopt *a, const struct socketopt *b);

/** Helper that compares two contexts
 *
 *  \return 0 if equal, 1 otherwise
 */
int compare_contexts(const muacc_context_t *a, const muacc_context_t *b);

/** Helper to print out the TLV buffer
 *  (Host byte order -> LSB first on many systems!)
 */
void tlv_print_buffer(char buf[], size_t buflen);

/** Compare tlv buffer with a value that was supposed to be written into it
 *  in host byte order
 *
 *  \return 0 if correctly written, 1 otherwise
 */
int compare_tlv(char *buf, size_t buf_pos, size_t buf_len, const void *value, size_t value_len);

#endif /* __TEST_UTIL_H__ */
