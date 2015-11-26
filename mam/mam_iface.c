/** \file mam_iface.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <sys/types.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ifaddrs.h>
#include <net/if.h>
#ifdef AF_LINK
#include <net/if_dl.h>
#endif
#ifdef AF_PACKET
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#endif
#include <net/route.h>
#include <netinet/if_ether.h>

#include "clib/dlog.h"
#include "clib/muacc_util.h"

#include "mam.h"
#include "mam_util.h"

#ifndef MAM_IF_NOISY_DEBUG0
#define MAM_IF_NOISY_DEBUG0 0
#endif

#ifndef MAM_IF_NOISY_DEBUG1
#define MAM_IF_NOISY_DEBUG1 0
#endif

#ifndef MAM_IF_NOISY_DEBUG2
#define MAM_IF_NOISY_DEBUG2 0
#endif

/* Function declaration: Add a new interface to list */
struct iface_list *_add_iface_to_list (GSList **ifacel, char *if_name);


/** Compare a src_prefix_list struct with a src_prefix_model
 *  Return 0 if they are equal, 1 if not, -1 on error */
int compare_src_prefix (gconstpointer listelement, gconstpointer model)
{
	struct src_prefix_model *m = (struct src_prefix_model *) model;
	struct src_prefix_list *cur = (struct src_prefix_list *) listelement;
	if (cur == NULL || model == NULL)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "WARNING: called with NULL argument\n");
		return -1;
	}

/*    DLOG(MAM_IF_NOISY_DEBUG2, "Comparing src_prefix_list item with model\n");
#if MAM_IF_NOISY_DEBUG2
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "Prefix =\t{");
	_mam_print_prefix(&sb, cur);
	strbuf_printf(&sb, "}, \nPrefix model =\t{ ");
	strbuf_printf(&sb, " if_name = %s,  ", (m->if_name!=NULL)?m->if_name:"ANY");
	_mam_print_prefix_list_flags(&sb, m->flags);
	strbuf_printf(&sb, " if_addrs = ");
	if(m->addr != NULL) _muacc_print_sockaddr(&sb, m->addr, m->addr_len); else strbuf_printf(&sb, "ANY ");
	strbuf_printf(&sb, "}\n");
	fprintf(stderr, "%s", strbuf_export(&sb));
	strbuf_release(&sb);
#endif*/

	/* different interface or family */
	if( ((cur->pfx_flags)^m->flags) & m->flags )
		return 1;
	if(m->family != 0 && cur->family != m->family)
		return 1;
	if(m->if_name != NULL && strcmp(cur->if_name, m->if_name) != 0)
		return 1;
	if( m->addr == NULL ||
		(m->family == AF_INET6 &&
		_cmp_in6_addr_with_mask(
			&(((struct sockaddr_in6 *) m->addr)->sin6_addr),
			&(((struct sockaddr_in6 *) cur->if_addrs->addr)->sin6_addr),
			&(((struct sockaddr_in6 *) cur->if_netmask)->sin6_addr)) == 0
		) || (
		m->family == AF_INET &&
		_cmp_in_addr_with_mask(
			&(((struct sockaddr_in *) m->addr)->sin_addr),
			&(((struct sockaddr_in *) cur->if_addrs->addr)->sin_addr),
			&(((struct sockaddr_in *) cur->if_netmask)->sin_addr)) == 0
		)
	)
	{
		DLOG(MAM_IF_NOISY_DEBUG2, "prefix matches model!\n");
		return 0;
	}
	else
		return 1;
}

/** From an old source prefix list, generate a new one
 *  that only includes prefixes matching certain criteria */
void filter_prefix_list (GSList *old, GSList **new, unsigned int pfx_flags, const char *if_name, int family, const struct sockaddr *addr)
{
    DLOG(MAM_IF_NOISY_DEBUG2, "filter prefix list\n");
	/* Set criteria for matching addresses */
	struct src_prefix_model m = { pfx_flags, if_name, family, addr };

	/* Go through the prefix list */
	while (old != NULL)
	{
		/* Find next element that matches our criteria */
		old = g_slist_find_custom(old->next, (gconstpointer) &m, &compare_src_prefix);
		if (old == NULL) break;

		/* Append matching element to new list */
		*new = g_slist_append(*new, old->data);
	}
}

/** Append an address to a sockaddr_list */
static int _append_sockaddr_list (
	struct sockaddr_list **dst,
    struct sockaddr *addr, 
	socklen_t addr_len )
{
	*dst = malloc(sizeof(struct sockaddr_list));
	if(*dst == NULL) { DLOG(1, "malloc failed"); return(-1); } 
	memset(*dst, 0, sizeof(struct sockaddr_list));
	(*dst)->addr = _muacc_clone_sockaddr(addr, addr_len);
	(*dst)->addr_len = addr_len;
	return(0);
}

/** Helper function that matches interface names.
 *  Returns 0 if the given ifname matches the given listelement's interface name
 */
int compare_if_name (gconstpointer listelement, gconstpointer ifname)
{
	struct iface_list *cur = (struct iface_list *) listelement;
	char *match_name = (char *) ifname;

	if (cur == NULL || match_name == NULL)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "WARNING: called with NULL argument\n");
		return -1;
	}

	if (cur->if_name != NULL && strcmp(cur->if_name, match_name) == 0)
	{
		// Interface names match
		return 0;
	}
	else
	{
		return 1;
	}

}

/** Add an interface to the interface list, if it does not exist there yet
 *  In any case, return a pointer to the interface list item
 */
struct iface_list *_add_iface_to_list (
	GSList **ifacel,
	char *if_name)
{
	if (if_name == NULL)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "Cannot add interface \"NULL\"!\n");
		return NULL;
	}
	GSList *ifacelistitem = NULL;

	/* Lookup this interface name in the interface list */
	ifacelistitem = g_slist_find_custom(*ifacel, (gconstpointer) if_name, &compare_if_name);

	if (ifacelistitem != NULL)
	{
		/* Interface name already found in list: Return this interface list item */
		DLOG(MAM_IF_NOISY_DEBUG2, "Interface %s already in list\n", if_name);
		return ifacelistitem->data;
	}
	else
	{
		DLOG(MAM_IF_NOISY_DEBUG2, "Adding interface %s to list\n", if_name);

		/* Interface name not found in list: Add it */
		struct iface_list *new = NULL;
		new = malloc(sizeof(struct iface_list));
		if (new == NULL)
		{
			DLOG(MAM_IF_NOISY_DEBUG1, "malloc for interface list element failed!\n");
			return NULL;
		}
		else
		{
			/* Create new interface list item */
			memset(new, 0, sizeof(struct iface_list));
			new->if_name = _muacc_clone_string(if_name);
			new->measure_dict = g_hash_table_new(g_str_hash, g_str_equal);

			/* Append to list */
			*ifacel = g_slist_append(*ifacel, (gpointer) new);

			return new;
		}
	}
}

/** Incorporate an address into the source prefix list:
 *  If a matching prefix exists, add it to this prefix' addr_list
 *  If no matching prefix exists yet, create one
 */
static void _scan_update_prefix (
	GSList **spfxl,
	struct iface_list *iflistentry,
	char *if_name, unsigned int if_flags,
	int family,
	struct sockaddr *addr,
	struct sockaddr *mask)
{
	GSList *cur = NULL;
	size_t family_size = (family == AF_INET)  ? sizeof(struct sockaddr_in)  :
	 					 (family == AF_INET6) ? sizeof(struct sockaddr_in6) :
						 -1;
	struct sockaddr_list *cus;
	
	
	/* scan through prefixes */
	struct src_prefix_model model = {PFX_ANY, if_name, family, addr, family_size};
	cur = g_slist_find_custom(*spfxl, (gconstpointer) &model, &compare_src_prefix);

	if (cur != NULL)
	{
		/* Prefix already exists within the list: append this address to its address list */

		for(cus = ((struct src_prefix_list *)cur->data)->if_addrs; cus->next != NULL; cus = cus->next);
		; 
		_append_sockaddr_list( &(cus->next), addr, family_size);
		return;			
	}
	
	/* we have a new prefix: append it to the prefix list */
	
	/* allocate memory */
	struct src_prefix_list *new = NULL;
	new = malloc(sizeof(struct src_prefix_list));
	if(new == NULL)
		{ DLOG(1, "malloc failed"); return; } 
	memset(new, 0, sizeof(struct src_prefix_list));
	
	/* copy data */
	new->if_name = _muacc_clone_string(if_name);
	new->family = family;
	new->if_flags = if_flags;
	_append_sockaddr_list( &(new->if_addrs), addr, family_size);
	new->if_netmask = _muacc_clone_sockaddr(mask, family_size);
	new->if_netmask_len = family_size;

	/* add pointer to the interface list item of the interface that this prefix belongs to */
	new->iface = iflistentry;

	new->measure_dict = g_hash_table_new(g_str_hash, g_str_equal);
	
	/* append to list */
	*spfxl = g_slist_append(*spfxl, (gpointer) new);

	return;
}

/** Scan for interfaces/addresses available on the host
 *  Create a new src_prefix_list and add all active interfaces, prefixes and addresses to it
 */
int update_src_prefix_list (mam_context_t *ctx )
{
	GSList **spfxl = &ctx->prefixes;
	GSList **ifacel = &ctx->ifaces;

    struct ifaddrs *ifaddr, *ifa;
    int family;

    DLOG(MAM_IF_NOISY_DEBUG0, "creating a list of the currently active interfaces\n");

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return(-1);
    }
	
	if(*spfxl != NULL) 
	{
		g_slist_free_full(*spfxl, &_free_src_prefix_list);
	}

	if(*ifacel != NULL)
	{
		g_slist_free_full(*ifacel, &_free_iface_list);
	}

    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
		if((ifa->ifa_flags & IFF_UP)==0) 
		{
            DLOG(MAM_IF_NOISY_DEBUG2, "%s: interface down - skipping\n", ifa->ifa_name);
        	continue;
		} 
		else if(ifa->ifa_addr == NULL) 
		{
            DLOG(MAM_IF_NOISY_DEBUG2, "%s: address family: (NULL) - skipping\n", ifa->ifa_name);
            continue;
		}
		
		family = ifa->ifa_addr->sa_family;
		
		if (family == AF_INET || family == AF_INET6)
        {
            DLOG(MAM_IF_NOISY_DEBUG2, "%s: adding address (", ifa->ifa_name);
			#if MAM_IF_NOISY_DEBUG2 != 0
        	/* Display interface name and family (including symbolic
               form of the latter for the common families) */
		    char addr[NI_MAXHOST];
		    char mask[NI_MAXHOST];
			int s;
            s = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	        s = getnameinfo(ifa->ifa_netmask,
	            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
	            mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s == 0)
			{
				fprintf(stderr, "family: %d%s, address: %s mask: %s)\n",
					 family,
					 (family == AF_INET) ?   " (AF_INET)" :
					 (family == AF_INET6) ?  " (AF_INET6)" : "",
					 addr, mask);
			}
			#endif

			/* add to interface list if it does not exist yet */
			struct iface_list *iflistentry = _add_iface_to_list( ifacel, ifa->ifa_name);
				 
			/* add to source prefix list */
			_scan_update_prefix( spfxl, iflistentry,
				ifa->ifa_name, ifa->ifa_flags,
				family, ifa->ifa_addr, ifa->ifa_netmask );
		}
    }

    freeifaddrs(ifaddr);
    return(0);
}

/** Tear down a interface list structure */
void _free_iface_list (gpointer data)
{
	struct iface_list *element = (struct iface_list *) data;

	if (element->if_name != NULL)
		free(element->if_name);

	if(element->policy_set_dict != NULL)
		g_hash_table_destroy(element->policy_set_dict);

	if(element->measure_dict != NULL)
		g_hash_table_destroy(element->measure_dict);

	free(element);

	return;
}

/** Tear down a source prefix list structure */
void _free_src_prefix_list (gpointer data)
{
	struct src_prefix_list *element = (struct src_prefix_list *) data;
	struct sockaddr_list *addrlist = NULL;
	struct sockaddr_list *curra = NULL;
	
	if (element->if_name != NULL)
		free(element->if_name);

	addrlist = element->if_addrs;
	while (addrlist != NULL)
	{
		curra = addrlist;
		addrlist = curra->next;
		
		if (curra->addr != NULL)
			free(curra->addr);
		
		free(curra);
	}
	
	if (element->if_netmask != NULL)
		free(element->if_netmask);

	if(element->evdns_base != NULL)
		evdns_base_free(element->evdns_base, 0);

	if(element->policy_set_dict != NULL)
		g_hash_table_destroy(element->policy_set_dict);

	if(element->measure_dict != NULL)
		g_hash_table_destroy(element->measure_dict);

	free(element);

	return;
}

