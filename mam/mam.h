#ifndef __MAM_H__
#define __MAM_H__

#include <event2/buffer.h>
#include <ltdl.h>

#include "../clib/muacc_types.h"

/** Context of an incoming request to the MAM */
typedef struct request_context {
	struct evbuffer 	*out;		/**< output buffer for libevent2 */
	struct evbuffer 	*in;		/**< input buffer for libevent2 */
	muacc_mam_action_t	action;		/**< socket call that this request is associated to */
	struct _muacc_ctx	*ctx;		/**< internal struct with relevant socket context data */
} request_context_t;

/** List of sockaddrs */
typedef struct sockaddr_list {
	struct sockaddr_list	*next;			/**< Next item in list */
	struct sockaddr			*addr;			/**< Socket address */
	size_t					addr_len;		/**< Length of socket address */
} sockaddr_list_t;

/** List of source prefixes */
typedef struct src_prefix_list {
	struct src_prefix_list 	*next;			/**< Next item in list */
	char 					*if_name;		/**< Name of the interface */
	unsigned int			if_flags;		/**< Flags from SIOCGIFFLAGS */
	struct sockaddr_list 	*if_addrs;		/**< List of socket addresses for this prefix */
	struct sockaddr			*if_netmask;	/**< Netmask of interface */
	size_t					if_netmask_len;	/**< Length of netmask */
} src_prefix_list_t;

/** Context of the MAM */
typedef struct mam_context {
	int						usage;			/**< Reference counter */
	struct src_prefix_list	*prefixes;		/**< Possible source prefixes on this system */
	lt_dlhandle				policy;			/**< Handle of policy module */
} mam_context_t;

/** Create and initialize the MAM context */
struct mam_context *mam_create_context();

/** (Re-)Initialize a MAM context */
int mam_init_context(struct mam_context *ctx);

/** Decrease reference counter and free struct if it reached 0 */
int mam_release_context(struct mam_context *ctx);

/** Print contents of a mam context structure */
void mam_print_context(mam_context_t *ctx);

#endif /* __MAM_H__ */
