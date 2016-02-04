/** \file test_util.h
 *	\brief Set of helpers for various test programs
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef __TEST_UTIL_H__
#define __TEST_UTIL_H__

#include "clib/muacc.h"
#include "lib/intents.h"

#ifndef memset_pattern4
void memset_pattern4 (void *dst, const void *pat, size_t len);
#endif

/** Helper that adds some sockopts to the context
 */
void ctx_add_socketopts(struct _muacc_ctx *ctx, struct socketopt *opts);

/** Helper that adds a sockopt with this intent (category) to the context */
void ctx_set_category(struct _muacc_ctx *ctx, intent_category_t cat);

void ctx_set_filesize(struct _muacc_ctx *ctx, int filesize);

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
