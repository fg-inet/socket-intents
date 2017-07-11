/** \file  mam/mam.h
 *  \brief Definition of structs and basic functions used by Multi Access Manager
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef __MAM_H__
#define __MAM_H__

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>

#include <uuid/uuid.h>

#include <ltdl.h>
#include <glib.h>

#include "muacc.h"
#include "socketset.h"
#include "config.h"

#include "mptcp_netlink_parser.h"

/** Context of an incoming request to the MAM */
typedef struct request_context {
	struct evbuffer 	*out;		/**< output buffer for libevent2 */
	struct evbuffer 	*in;		/**< input buffer for libevent2 */
	struct evdns_base	*evdns_base;	/**< dns base used in between socket calls */
	muacc_mam_action_t	action;		/**< socket call that this request is associated to */
	unsigned int		policy_calls_performed; /**< Policy functions that we have already called */
	struct _muacc_ctx	*ctx;		/**< internal struct with relevant socket context data */
	struct socketlist	*sockets;	/**< list of existing sockets for socketchoose */
	struct mam_context	*mctx;		/**< pointer to current mam context */
	void 			*policy_context;/**< pointer to store policy data */
} request_context_t;

#define MAM_POLICY_RESOLVE_CALLED 0x001
#define MAM_POLICY_CONNECT_CALLED 0x002
#define MAM_POLICY_SOCKETCONNECT_CALLED 0x004
#define MAM_POLICY_SOCKETCHOOSE_CALLED 0x008

/** List of sockaddrs */
typedef struct sockaddr_list {
	struct sockaddr_list	*next;			/**< Next item in list */
	struct sockaddr			*addr;			/**< Socket address */
	socklen_t				addr_len;		/**< Length of socket address */
} sockaddr_list_t;

/** Flags used for a prefix */

#define PFX_ANY				0x0000	/**< the flags doesn't matter */
#define PFX_ENABLED			0x0001	/**< the prefix has been enabled */
#define PFX_CONF			0x0002	/**< the prefix has been mentioned in the configuration */
#define PFX_CONF_PFX		0x0004	/**< the prefix has been configured through an prefix statement */
#define PFX_CONF_IF			0x0008	/**< the prefix has been configured through an interface statement */
#define PFX_SCOPE_GLOBAL	0x0100
#define PFX_SCOPE_LL		0x0200


/** List of source prefixes */
typedef struct src_prefix_list {
	unsigned int			pfx_flags;			/**< Flags of that prefix */
	char 					*if_name;			/**< Name of the interface */
	struct iface_list		*iface;				/**< Interface this prefix belongs to */
	int 					family;				/**< Address family */
	unsigned int			if_flags;			/**< Flags from SIOCGIFFLAGS */
	struct sockaddr_list 	*if_addrs;			/**< List of socket addresses for this prefix */
	struct sockaddr			*if_netmask;		/**< Netmask of interface */
	socklen_t				if_netmask_len;		/**< Length of netmask */
	struct evdns_base 		*evdns_base; 		/**< DNS base to do look ups for that prefix */
	GHashTable 				*policy_set_dict; 	/**< dictionary for policy configuration */
	void					*policy_info;		/**< Policy-internal data structure for additional information */
	GHashTable				*measure_dict;		/**< Dictionary for measurement data of this prefix */
} src_prefix_list_t;

/** list of interfacses */
typedef struct iface_list {
	char 					*if_name;			/**< Name of the interface */
	GHashTable 				*policy_set_dict; 	/**< dictionary for policy configuration */
	GHashTable				*measure_dict;		/**< Dictionary for measurement data of this interface */
} iface_list_t;

/** Context of the MAM */
typedef struct mam_context {
	int						usage;				/**< Reference counter */
	GSList					*prefixes;			/**< Possible source prefixes on this system */
	GSList					*ifaces;		/**< Interfaces of this system */
	lt_dlhandle				policy;				/**< Handle of policy module */
	struct event_base 		*ev_base;			/**< Libevent Event Base */
	struct evdns_base 		*evdns_default_base;/**< DNS base to do look ups if all other fails */
	GHashTable 				*policy_set_dict; 	/**< dictionary for policy configuration */
	GSList					*clients; 	 		/**< list of all applications that are connected to the MAM */
	GHashTable				*state; 			/** global mam state */
} mam_context_t;

/** List of clients connected to the MAM */
typedef struct _client_list {
	int						client_sk;
	uuid_t					id;
	GSList					*sockets;
	uint64_t				inode;
	GHashTable				*flow_table;
	void (*callback_function)(GSList*);
} client_list_t;

/** List of sockets opened by a client application */
typedef struct _socket_list {
	int 					sk;
} socket_list_t;

/** Model that describes a prefix, used for lookup in the list */
struct src_prefix_model {
	unsigned int			flags;
	const char				*if_name;
	int						family;
	const struct sockaddr	*addr;
	size_t					addr_len;
};

/** Create and initialize the MAM context */
struct mam_context *mam_create_context();

/** (Re-)Initialize a MAM context */
int mam_init_context(struct mam_context *ctx);

/** Decrease reference counter and free struct if it reached 0 */
int mam_release_context(struct mam_context *ctx);

/** Print contents of a mam context structure */
void mam_print_context(mam_context_t *ctx);

/** Print contents of a request context: associated _muacc_ctx and mam_context */
void mam_print_request_context(request_context_t *ctx);

/** Release request context */
void mam_release_request_context(request_context_t *ctx);

/** update the source prefix list within the mam_context using getifaddrs()*/
int update_src_prefix_list (mam_context_t *ctx);

/** get the src_prefix_list for a specific interface or prefix
  */
struct src_prefix_list *lookup_source_prefix (
 	struct src_prefix_list *spfxl,	/**< [in] list element to start scanning */
	unsigned int pfx_flags,			/**< [in] prefix flags that have to be set */
	const char *if_name,            /**< [in] interface name to look for – NULL ist a wildcard */
	int family,                     /**< [in] address family to look for */
	const struct sockaddr *addr     /**< [in] prefix to scan for (uses mask from spfxl)  – NULL ist a wildcard */
);

/** Helper function for finding a specific prefix from the prefix list
 *  Returns 0 for the matching element, 1 otherwise
 *  To be called from g_slist_find_custom() */
int compare_src_prefix(
	gconstpointer listelement, 		/**< [in] list element to start scanning */
	gconstpointer model				/**< [in] src_prefix_model that contains properties to look for */
);

/** Helper function for finding a specific interface from the interface list
 *  Returns 0 for the matching element, 1 otherwise
 *  To be called from g_slist_find_custom() */
int compare_if_name (
	gconstpointer listelement, 		/**< [in] list element to compare */
	gconstpointer ifname			/**< [in] interface name we are looking for */
);

/** Helper function for comparing all elements of a list against the model
 *  From this elements, makes a new list (only the data pointers, no deep copy!)
 */
void filter_prefix_list (
	GSList *old, 					/**< [in] list to filter */
	GSList **new,					/**< [out] pointer to the filtered list */
	unsigned int pfx_flags,			/**< [in] flags to filter for, or PFX_ANY */
	const char *if_name,			/**< [in] interface name to filter for, or NULL (any) */
	int family,						/**< [in] protocol family to filter for, or AF_UNSPEC (any) */
	const struct sockaddr *addr		/**< [in] socket address to filter for, or NULL (any) */
	);

/** config read function */
void mam_read_config(int config_fd, char **p_file_out, struct mam_context *ctx);

/* helper functions */
#include "mam_util.h"

#endif /* __MAM_H__ */
