/** \file  muacc.h
 *  \brief Defines data structures for generic muacc library
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef __MUACC_H__
#define __MUACC_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include <uuid/uuid.h>

#include "strbuf.h"
#include "dlog.h"

typedef enum
{
	muacc_act_connect_req,					/**< is from a connect */
	muacc_act_connect_resp,
	muacc_act_getaddrinfo_resolve_req,	    /**< is from a getaddrinfo, pre resolving */
	muacc_act_getaddrinfo_resolve_resp,
	muacc_act_socketconnect_req,			/**< is from a socketconnect, requests a new socket */
	muacc_act_socketconnect_resp,			/**< socketconnect response, create new socket */
	muacc_act_socketconnect_fallback,		/**< socketconnect falls back to getaddrinfo + connect */
	muacc_act_socketchoose_req,				/**< choose between existing set of sockets or open new one */
	muacc_act_socketchoose_resp_existing,	/**< socketchoose response, choose existing socket */
	muacc_act_socketchoose_resp_new,		/**< socketchoose response, create new socket */
	muacc_error_unknown_request,			/**< indicates an error */
} muacc_mam_action_t;

/** Linked list of socket options to be set */
typedef struct socketopt {
	int 				level;				/**< Level at which the socket option is valid */
	int 				optname;			/**< Identifier of the option */
	void 				*optval;			/**< Pointer to the value */
	socklen_t 			optlen;				/**< Length of the value */
	int					returnvalue;		/**< Return value of setsockopt() if applicable */
	int					flags;				/**< Flags */
	struct socketopt 	*next;				/**< Pointer to the next socket option */
} socketopt_t;

#define SOCKOPT_IS_SET 0x0001 	/**< Sockopt has been set on the socket */
#define SOCKOPT_OPTIONAL 0x0002	/**< If setting the option fails, still continue */

/** Context identifier that is unique per MAM socket in a client */
//typedef uuid_t muacc_ctxid_t;

/** Inode of a client
	Used as an identifier that is unique per MPTCP session */
typedef uint64_t muacc_ctxino_t;

/** Internal muacc context struct
	All data will be serialized and sent to MAM */
struct _muacc_ctx {
	uuid_t		ctxid;					/**< identifier for the context if sharing mamsock */
    muacc_ctxino_t      ctxino;                 /**< inode of the socket (used as identifier for MPTCP sessions) */
	int					sockfd;					/**< filedecriptor of the socket */
	unsigned int		calls_performed;		/**< contains flags of which socket call have been performed*/
	int					domain;					/**< communication domain of the socket (e.g. AF_INET) */
	int					type;					/**< communication semantics, e.g. SOCK_STREAM or SOCK_DGRAM */
	int					protocol;				/**< may specify a particular protocol in this family */
	struct sockaddr 	*bind_sa_req;       	/**< local address requested by bind call */
	socklen_t 			 bind_sa_req_len;      	/**< length of bind_sa_req*/
	struct sockaddr 	*bind_sa_suggested;     /**< local address suggested by MAM */
	socklen_t 			 bind_sa_suggested_len; /**< length of bind_sa_res*/
	char 				*remote_hostname;      	/**< hostname to resolve */
	char				*remote_service;		/**< remote service to connect to */
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
	socketset_file,			/**< file descriptor of an existing socket from a socketset */
	calls_performed,		/**< flags of which socket calls have already been performed */
	ctxid = 0x08,			/**< identifier for the context if sharing mamsock */
    ctxino,                 /**< inode of the socket (used as identifier for MPTCP sessions) */
	sockfd,
	domain,					/**< protocol family */
	type,					/**< socket type */
	protocol,				/**< specific protocol in the given family */
	bind_sa_req = 0x13, 	/**< local address requested */
	bind_sa_res,        	/**< local address choosen by mam */
	remote_hostname = 0x21,	/**< remote host name */
	remote_service,	   		/**< remote service name */
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

#endif /* __MUACC_H__ */
