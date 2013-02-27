/** /file Stuff to manipulate "_muacc_ctx"
 *
 */

#ifndef __MUACC_CTX_H__
#define __MUACC_CTX_H__ 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "muacc.h"
#include "muacc_types.h"



/** Helper to allocate and initalize _muacc_ctx
 *
 */
struct _muacc_ctx *_muacc_create_ctx();

/** Helper to maintain refernece count on _muacc_ctx
 *
 */
int _muacc_retain_ctx(struct _muacc_ctx *_ctx);

/** Helper to free _muacc_ctx if reference count reaches 0
 *
 */
int _muacc_free_ctx (struct _muacc_ctx *_ctx);


/** Helper doing locking simulation - lock part
 *
 * just to make sure that we have no
 * interleaving requests on a single socket
 */
int _lock_ctx (struct _muacc_ctx *_ctx);

/** Helper doing locking simulation - unlock part
 *
 * just to make sure that we have no
 * interleaving requests on a single socket
 */
int _unlock_ctx (struct _muacc_ctx *_ctx);

/** Serialize the _ctx packing struct in a series of TLVs
 *
 * this has to be kept in sync with the members of _muacc_ctx
 * NULL pointers will be skipped
 *
 */
size_t _muacc_pack_ctx(
	char *buf,						/**< [in]		buffer to write TLVs to */
	size_t *pos,					/**< [in,out]	position within buf */
	size_t len,						/**< [in]		length of buf	*/
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
	size_t data_len,				/**< [in]		length of the TLV */
	struct _muacc_ctx *_ctx			/**< [in]		context to put parsed data in */
);

/* helper to print ctx
 *
 */
void _muacc_print_ctx(char *buf, size_t *buf_pos, size_t buf_len, const struct _muacc_ctx *_ctx);

#endif
