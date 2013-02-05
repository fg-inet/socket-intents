#ifndef __MUACC_CTX_H__
#define __MUACC_CTX_H__ 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

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
	char *buf;                        		/**> buffer for i/o */
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

/** Helper serialzing _ctx in TLVs
 *
 */
size_t _muacc_pack_ctx(char *buf, size_t *pos, size_t len, struct _muacc_ctx *ctx);

/** Helper parsing a single TLV and pushing the data to _ctx
 *
 * keeps memory consistent
 */
int _muacc_unpack_ctx(muacc_tlv_t tag, const void *data, size_t data_len, struct _muacc_ctx *_ctx);


#endif
