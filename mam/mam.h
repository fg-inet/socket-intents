#ifndef __MAM_H__
#define __MAM_H__ 1

#include <event2/buffer.h>

#include "../clib/muacc_types.h"

/** Context of an incoming request to the MAM */
typedef struct request_context {
	struct evbuffer 	*out;		/**< output buffer for libevent2 */
	struct evbuffer 	*in;		/**< input buffer for libevent2 */
	muacc_mam_action_t	action;		/**< socket call that this request is associated to */
	struct _muacc_ctx	*ctx;		/**< internal struct with relevant socket context data */
} request_context_t;

#endif
