/** /file Stuff to manipulate "_muacc_ctx"
 *
 */

#ifndef __MUACC_CTX_H__
#define __MUACC_CTX_H__ 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <event2/buffer.h>

#include "muacc.h"
#include "muacc_tlv.h"

/** Linked list of socket options */
typedef struct socketopt {
	int 				level;				/**> Level at which the socket option is valid */
	int 				optname;			/**> Identifier of the option */
	void 				*optval;			/**> Pointer to the value */
	socklen_t 			optlen;				/**> Length of the value */
	struct socketopt 	*next;				/**> Pointer to the next socket option */
} socketopt_t;

/** Internal muacc context struct */
struct _muacc_ctx {
	int usage;                          	/**> reference counter */
	uint8_t locks;                      	/**> lock to avoid multiple concurrent requests to MAM */
	int mamsock;                        	/**> socket to talk to/in MAM */
	struct evbuffer *out;					/**> output buffer when used with libevent2 */
	struct evbuffer *in;					/**> input buffer when used with libevent2 */
	muacc_mam_action_t state;				/**> state machine state */
	/* fields below will be serialized */
	struct sockaddr *bind_sa_req;       	/**> local address requested */
	socklen_t 		 bind_sa_req_len;      	/**> length of bind_sa_req*/
	struct sockaddr *bind_sa_res;       	/**> local address choosen by MAM */
	socklen_t 		 bind_sa_res_len;      	/**> length of bind_sa_res*/
	struct sockaddr *remote_sa_req;     	/**> remote address requested */
	socklen_t 		 remote_sa_req_len;    	/**> length of remote_sa_req*/
	char 			*remote_hostname;      	/**> hostname to resolve */
	struct addrinfo	*remote_addrinfo_hint;	/**> hints for resolving */
	struct addrinfo	*remote_addrinfo_res;	/**> candidate remote addresses (sorted by MAM preference) */
	struct sockaddr *remote_sa_res;     	/**> remote address choosen in the end */
	socklen_t 		 remote_sa_res_len;    	/**> length of remote_sa_res */
	socketopt_t		*socket_options;		/**> associated socket options */
};

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
	char *buf,						/**> [in]		buffer to write TLVs to */
	size_t *pos,					/**> [in,out]	position within buf */
	size_t len,						/**> [in]		length of buf	*/
	const struct _muacc_ctx *ctx	/**> [in]		context to pack */
);

/** parse a single TLV and push its content to the respective member of _muacc_ctx
 *
 * this has to be kept in sync with the members of _muacc_ctx
 * has to keep memory consistent (free stuff changed/overwritten)
 */
int _muacc_unpack_ctx(
	muacc_tlv_t tag,				/**> [in]		tag of the TLV */
	const void *data,				/**> [in]		value of the TLV */
	size_t data_len,				/**> [in]		length of the TLV */
	struct _muacc_ctx *_ctx			/**> [in]		context to put parsed data in */
);

/* helper to print ctx
 *
 */
void _muacc_print_ctx(char *buf, size_t *buf_pos, size_t buf_len, const struct _muacc_ctx *_ctx);

#endif
