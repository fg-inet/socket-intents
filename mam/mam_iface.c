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

#include "../config.h"

#include "mam.h"
#include "mam_util.h"

#include "../lib/dlog.h"
#include "../lib/muacc_util.h"


#ifndef MAM_IF_NOISY_DEBUG0
#define MAM_IF_NOISY_DEBUG0 0
#endif

#ifndef MAM_IF_NOISY_DEBUG1
#define MAM_IF_NOISY_DEBUG1 0
#endif

#ifndef MAM_IF_NOISY_DEBUG2
#define MAM_IF_NOISY_DEBUG2 0
#endif


/** check wheather two ipv4 addresses are in the same subnet */
int _cmp_in_addr_with_mask(
	struct in_addr *a,		
	struct in_addr *b,
	struct in_addr *mask	/**< the subnet mask */
){
	return( (a->s_addr ^ b->s_addr) & mask->s_addr );	
}

/** check wheather two ipv6 addresses are in the same subnet */
int _cmp_in6_addr_with_mask(
	struct in6_addr *a,		
	struct in6_addr *b,
	struct in6_addr *mask	/**< the subnet mask */
){
	for(int i=0; i<16; i++)
	{
		if( (((a->s6_addr)[i] ^ (b->s6_addr)[i]) & (mask->s6_addr)[i]) != 0 )
			return (i+1);
	}
	return(0);	
}

struct src_prefix_list *lookup_source_prefix (
	struct src_prefix_list *spfxl,
	const char *if_name,
	int family,
	const struct sockaddr *addr
) {

	/* scan through prefixes */
	for(struct src_prefix_list *cur = spfxl; cur != NULL; cur = cur->next)
	{
		/* different interface or family */
		if(cur->family != family)
			continue;
		if(if_name != NULL && strcmp(cur->if_name, if_name) != 0)
			continue;
		if( addr == NULL ||
			(family == AF_INET6 &&
			_cmp_in6_addr_with_mask(
				&(((struct sockaddr_in6 *) addr)->sin6_addr), 
				&(((struct sockaddr_in6 *) cur->if_addrs->addr)->sin6_addr),
				&(((struct sockaddr_in6 *) cur->if_netmask)->sin6_addr))
		    ) == 0|| (
			family == AF_INET &&
			_cmp_in_addr_with_mask(
				&(((struct sockaddr_in *) addr)->sin_addr),
				&(((struct sockaddr_in *) cur->if_addrs->addr)->sin_addr),
				&(((struct sockaddr_in *) cur->if_netmask)->sin_addr)) == 0
		))
		{
			return cur;			
		}
	}
	return NULL;	
}


int _append_sockaddr_list (
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
	
																																																	   
void _scan_update_prefix (
	struct src_prefix_list **spfxl,
	char *if_name, unsigned int if_flags,
	int family,
	struct sockaddr *addr,
	struct sockaddr *mask)
{
	struct src_prefix_list *cur;
	struct src_prefix_list *last;
	struct src_prefix_list *new;
	size_t family_size = (family == AF_INET)  ? sizeof(struct sockaddr_in)  :
	 					 (family == AF_INET6) ? sizeof(struct sockaddr_in6) :
						 -1;
	struct sockaddr_list *cus;
	
	
	/* scan through prefixes */
	cur = lookup_source_prefix (*spfxl,	if_name, family, addr);
	if (cur != NULL)
	{
		for(cus = cur->if_addrs; cus->next != NULL; cus = cus->next);; 
		_append_sockaddr_list( &(cus->next), addr, family_size);
		return;			
	}
	
	/* we have a new prefix */
	
	/* allocate memory */
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
	
	/* save new one */
	if(*spfxl != NULL) 
	{
		for(last = *spfxl; last->next != NULL; last = last->next);; 
		last->next = new;
	}
	else
		*spfxl = new;
	
	return;
}

int update_src_prefix_list (mam_context_t *ctx ){

	struct src_prefix_list **spfxl = &(ctx->prefixes);
    struct ifaddrs *ifaddr, *ifa;
    int family;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return(-1);
    }
	
	if(*spfxl != NULL) 
	{
		_free_src_prefix_list(*spfxl);
		*spfxl = NULL;		
	}
	
    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        family = ifa->ifa_addr->sa_family;

		if((ifa->ifa_flags & IFF_UP)==0) 
		{
            DLOG(MAM_IF_NOISY_DEBUG0, "%s: interface down skipping\n", ifa->ifa_name);
        	continue;
		} 
		else if(ifa->ifa_addr == NULL) 
		{
            DLOG(MAM_IF_NOISY_DEBUG0, "%s: address family: (NULL) - skipping\n", ifa->ifa_name);
            continue;
		}
		else if (family == AF_INET || family == AF_INET6) 
        {
			#if MAM_IF_NOISY_DEBUG1 != 0
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
         	DLOG(MAM_IF_NOISY_DEBUG1, "scanning for family: %d%s, address: %s mask: %s\n",
                 family,
                 (family == AF_INET) ?   " (AF_INET)" :
                 (family == AF_INET6) ?  " (AF_INET6)" : "",
				 addr, mask);
			#endif
				 
			/* add to our structure */
			_scan_update_prefix( spfxl,
				ifa->ifa_name, ifa->ifa_flags,
				family, ifa->ifa_addr, ifa->ifa_netmask );
		}
        family = ifa->ifa_addr->sa_family;
    }

    freeifaddrs(ifaddr);
    return(0);
}

int _free_src_prefix_list (struct src_prefix_list *spfxl) 
{
	struct src_prefix_list *nextp = NULL;
	struct src_prefix_list *currp = NULL;
	struct sockaddr_list *nexta = NULL;
	struct sockaddr_list *curra = NULL;
	
	nextp = spfxl;
	while (nextp != NULL)
	{
		currp = nextp;
		nextp = currp->next;
		
		if (currp->if_name != NULL)		
			free(currp->if_name);
		
		nexta = currp->if_addrs;
		while (nexta != NULL)
		{
			curra = nexta;
			nexta = curra->next;
			
			if (curra->addr != NULL)	
				free(curra->addr);
			
			free(curra);
		}
		
		if (currp->if_netmask != NULL)
			free(currp->if_netmask);
		
		free(currp);
	}
	
	return(0);
}

