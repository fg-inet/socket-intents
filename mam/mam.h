/* \file  mam.h
 * \brief Definition of structs and basic functions used by Multi Access Manager
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

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>

#include <ltdl.h>
#include <glib.h>

#include "../lib/muacc.h"

/** Context of an incoming request to the MAM */
typedef struct request_context {
	struct evbuffer 	*out;		/**< output buffer for libevent2 */
	struct evbuffer 	*in;		/**< input buffer for libevent2 */
	muacc_mam_action_t	action;		/**< socket call that this request is associated to */
	struct _muacc_ctx	*ctx;		/**< internal struct with relevant socket context data */
	struct mam_context	*mctx;		/**< pointer to current mam context */
} request_context_t;

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
	struct src_prefix_list 	*next;				/**< Next item in list */
	unsigned int			pfx_flags;			/**< Flags of that prefix */
	char 					*if_name;			/**< Name of the interface */
	int 					family;				/**< Address family */
	unsigned int			if_flags;			/**< Flags from SIOCGIFFLAGS */
	struct sockaddr_list 	*if_addrs;			/**< List of socket addresses for this prefix */
	struct sockaddr			*if_netmask;		/**< Netmask of interface */
	socklen_t				if_netmask_len;		/**< Length of netmask */
	struct evdns_base 		*evdns_base; 		/**< DNS base to do look ups for that prefix */
	GHashTable 				*policy_set_dict; 	/**< dictionary for policy configuration */
} src_prefix_list_t;

/** list of interfacses */
typedef struct iface_list {
	struct iface_list 		*next;				/**< Next item in list */
	char 					*if_name;			/**< Name of the interface */
	GHashTable 				*policy_set_dict; 	/**< dictionary for policy configuration */
} iface_list_t;

/** Context of the MAM */
typedef struct mam_context {
	int						usage;			/**< Reference counter */
	struct src_prefix_list	*prefixes;		/**< Possible source prefixes on this system */
	lt_dlhandle				policy;			/**< Handle of policy module */
	struct event_base 		*ev_base;			/**< Libevent Event Base */
	struct evdns_base 		*evdns_default_base; /**< DNS base to do look ups if all other fails */
	GHashTable 				*policy_set_dict; /**< dictionary for policy configuration */
} mam_context_t;

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

/** config read function */
void mam_read_config(int config_fd, char **p_file_out, struct mam_context *ctx);

/* helper functions */
#include "mam_util.h"

#endif /* __MAM_H__ */
