
#ifndef __MUACC_TYPES_H__
#define __MUACC_TYPES_H__ 1

#include <event2/buffer.h>

typedef enum
{
	muacc_act_connect_req,					/**< is from a connect */
	muacc_act_connect_resp,
	muacc_act_getaddrinfo_preresolve_req,	/**< is from a getaddrinfo, pre resolving */
	muacc_act_getaddrinfo_preresolve_resp,
	muacc_act_getaddrinfo_postresolve_req,	/**< is from a getaddrinfo, post resolving,
	 	 	 	 	 	 	 	 	 	 	  *     only called if muacc_action_getaddrinfo_preresolve did not
											  *     provide an address after calling getaddrinfo ourselves */
	muacc_act_getaddrinfo_postresolve_resp,
	muacc_act_setsocketopt_req,				/**< is from a setsocketopt */
	muacc_act_setsocketopt_resp
} muacc_mam_action_t;

/** Linked list of socket options */
typedef struct socketopt {
	int 				level;				/**< Level at which the socket option is valid */
	int 				optname;			/**< Identifier of the option */
	void 				*optval;			/**< Pointer to the value */
	socklen_t 			optlen;				/**< Length of the value */
	struct socketopt 	*next;				/**< Pointer to the next socket option */
} socketopt_t;

/** Internal muacc context struct */
struct _muacc_ctx {
	int usage;                          	/**< reference counter */
	uint8_t locks;                      	/**< lock to avoid multiple concurrent requests to MAM */
	int mamsock;                        	/**< socket to talk to/in MAM */
	struct evbuffer *out;					/**< output buffer when used with libevent2 */
	struct evbuffer *in;					/**< input buffer when used with libevent2 */
	muacc_mam_action_t state;				/**< state machine state */
	/* fields below will be serialized */
	struct sockaddr *bind_sa_req;       	/**< local address requested */
	socklen_t 		 bind_sa_req_len;      	/**< length of bind_sa_req*/
	struct sockaddr *bind_sa_res;       	/**< local address choosen by MAM */
	socklen_t 		 bind_sa_res_len;      	/**< length of bind_sa_res*/
	struct sockaddr *remote_sa_req;     	/**< remote address requested */
	socklen_t 		 remote_sa_req_len;    	/**< length of remote_sa_req*/
	char 			*remote_hostname;      	/**< hostname to resolve */
	struct addrinfo	*remote_addrinfo_hint;	/**< hints for resolving */
	struct addrinfo	*remote_addrinfo_res;	/**< candidate remote addresses (sorted by MAM preference) */
	struct sockaddr *remote_sa_res;     	/**< remote address choosen in the end */
	socklen_t 		 remote_sa_res_len;    	/**< length of remote_sa_res */
	struct socketopt	*sockopts_current;		/**< socket options currently set */
	struct socketopt	*sockopts_suggested;	/**< socket options suggested by MAM */
};

typedef enum
{
	eof = 0x00,		    	/**< end of TLV data – always 0 bytes */
	action,					/**< action triggering request */
	bind_sa_req = 0x12, 	/**< local address requested */
	bind_sa_res,        	/**< local address choosen by mam */
	remote_hostname = 0x20,	/**< remote host name */
	remote_srvname,	   		/**< remote service name */
	remote_sa_req,     		/**< remote address requested */
	remote_addrinfo_hint,	/**< candidate remote addresses (sorted by mam preference) */
	remote_addrinfo_res,	/**< candidate remote addresses (sorted by mam preference) */
	remote_sa_res     		/**< remote address choosen */
} muacc_tlv_t;

#endif /* __MUACC_TYPES_H__ */
