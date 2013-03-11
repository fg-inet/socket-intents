
#ifndef __MUACC_TYPES_H__
#define __MUACC_TYPES_H__ 1

#include <event2/buffer.h>

typedef enum
{
	muacc_act_connect_req,					/**< is from a connect */
	muacc_act_connect_resp,
	muacc_act_getaddrinfo_resolve_req,	    /**< is from a getaddrinfo, pre resolving */
	muacc_act_getaddrinfo_resolve_resp,
} muacc_mam_action_t;

/** Linked list of socket options */
typedef struct socketopt {
	int 				level;				/**< Level at which the socket option is valid */
	int 				optname;			/**< Identifier of the option */
	void 				*optval;			/**< Pointer to the value */
	socklen_t 			optlen;				/**< Length of the value */
	struct socketopt 	*next;				/**< Pointer to the next socket option */
} socketopt_t;

typedef uint64_t muacc_ctxid_t;
/** Internal muacc context struct */
struct _muacc_ctx {
	int 				usage;                  /**< reference counter */
	uint8_t 			locks;                  /**< lock to avoid multiple concurrent requests to MAM */
	int 				mamsock;                /**< socket to talk to/in MAM */
	struct evbuffer 	*out;					/**< output buffer when used with libevent2 */
	struct evbuffer 	*in;					/**< input buffer when used with libevent2 */
	muacc_mam_action_t	state;					/**< state machine state */
	/* fields below will be serialized */
	muacc_ctxid_t		ctxid;					/**< identifyer for the context if sharing mamsock */
	unsigned int		calls_performed;		/**< contains flags of which socket call have been performed*/
	struct sockaddr 	*bind_sa_req;       	/**< local address requested by bind call */
	socklen_t 			 bind_sa_req_len;      	/**< length of bind_sa_req*/
	struct sockaddr 	*bind_sa_suggested;     /**< local address suggested by MAM */
	socklen_t 			 bind_sa_suggested_len; /**< length of bind_sa_res*/
	char 				*remote_hostname;      	/**< hostname to resolve */
	struct addrinfo		*remote_addrinfo_hint;	/**< hints for resolving */
	struct addrinfo		*remote_addrinfo_res;	/**< candidate remote addresses (sorted by MAM preference) */
	struct sockaddr 	*remote_sa;     		/**< remote address choosen in the end */
	socklen_t 			 remote_sa_len;    		/**< length of remote_sa_res */
	struct socketopt	*sockopts_current;		/**< socket options currently set */
	struct socketopt	*sockopts_suggested;	/**< socket options suggested by MAM */
};

typedef enum
{
	eof = 0x00,		    	/**< end of TLV data – always 0 bytes */
	action,					/**< action triggering request */
	calls_performed,		/**< flags of which socket calls have already been performed */
	ctxid = 0x08,			/**< identifyer for the context if sharing mamsock */
	bind_sa_req = 0x12, 	/**< local address requested */
	bind_sa_res,        	/**< local address choosen by mam */
	remote_hostname = 0x20,	/**< remote host name */
	remote_srvname,	   		/**< remote service name */
	remote_addrinfo_hint,	/**< candidate remote addresses (sorted by mam preference) */
	remote_addrinfo_res,	/**< candidate remote addresses (sorted by mam preference) */
	remote_sa,     			/**< remote address choosen */
	sockopts_current,		/**< list of currently set sockopts */
	sockopts_suggested		/**< list of sockopts suggested by MAM */
} muacc_tlv_t;

/** Flags for storing which socketcalls have been performed */
#define MUACC_SOCKET_CALLED 0x0001
#define MUACC_GETADDRINFO_CALLED 0x0004
#define MUACC_BIND_CALLED 0x0008
#define MUACC_CONNECT_CALLED 0x0010
#define MUACC_CLOSE_CALLED 0x0020

#endif /* __MUACC_TYPES_H__ */
