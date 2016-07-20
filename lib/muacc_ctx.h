/** \file  muacc_ctx.h
 *  \brief Functions to manipulate and print "_muacc_ctx" and to pack it to a TLV buffer
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef __MUACC_CTX_H__
#define __MUACC_CTX_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "clib/muacc.h"

/** Type for uuid
 *
 */
typedef unsigned char uuid_t[16];

/** Helper to allocate and initialize _muacc_ctx
 *
 */
struct _muacc_ctx *_muacc_create_ctx();

/** Helper that computes a new context ID from a counter and the current PID
 *
 */
//muacc_ctxid_t _get_ctxid();

/** Helper to free _muacc_ctx if reference count reaches 0
 *
 */
int _muacc_free_ctx (struct _muacc_ctx *_ctx);

/* helper to print ctx
 *
 */
void _muacc_print_ctx(strbuf_t *sb, const struct _muacc_ctx *_ctx);

/** Serialize the _ctx packing struct in a series of TLVs
 *
 * this has to be kept in sync with the members of _muacc_ctx
 * NULL pointers will be skipped
 *
 */
ssize_t _muacc_pack_ctx(
	char *buf,						/**< [in]		buffer to write TLVs to */
	ssize_t *pos,					/**< [in,out]	position within buf */
	ssize_t len,						/**< [in]		length of buf	*/
	const struct _muacc_ctx *ctx	/**< [in]		context to pack */
);

/** parse a single TLV and push its content to the respective member of _muacc_ctx
 *
 * this has to be kept in sync with the members of _muacc_ctx
 * has to keep memory consistent (free stuff changed/overwritten)
 */
int _muacc_unpack_ctx(
	muacc_tlv_t tag,				/**< [in]		tag of the TLV */
	const void *data,				/**< [in]		value of the TLV */
	ssize_t data_len,				/**< [in]		length of the TLV */
	struct _muacc_ctx *_ctx			/**< [in]		context to put parsed data in */
);

#endif
