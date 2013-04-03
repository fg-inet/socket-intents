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
#include "../clib/dlog.h"
#include "../clib/muacc_util.h"


#define MAM_IF_NOISY_DEBUG0 1

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

int _append_sockaddr_list (
	struct sockaddr_list **dst,
    struct sockaddr *addr, 
	socklen_t addr_len )
{
	*dst = malloc(sizeof(struct sockaddr_list));
	if(*dst == NULL) { DLOG(MAM_IF_NOISY_DEBUG0, "malloc failed"); return(-1); } 
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
	struct src_prefix_list **last = spfxl;
	struct src_prefix_list *new;
	size_t family_size = (family == AF_INET)  ? sizeof(struct sockaddr_in)  :
	 					 (family == AF_INET6) ? sizeof(struct sockaddr_in6) :
						 -1;
	struct sockaddr_list *cus;
	
	
	/* scan through prefixes */
	for(struct src_prefix_list *cur = *spfxl; cur != NULL; cur = cur->next)
	{
		last = &(cur->next);
		
		/* different interface or family */
		if(cur->family != family)
			continue;
		if(strcmp(cur->if_name, if_name) != 0)
			continue;
		if((family == AF_INET6 &&
			_cmp_in6_addr_with_mask(
				&(((struct sockaddr_in6 *) addr)->sin6_addr), 
				&(((struct sockaddr_in6 *) cur->if_addrs->addr)->sin6_addr),
				&(((struct sockaddr_in6 *) cur->if_netmask)->sin6_addr))
		    ) || (
			family == AF_INET &&
			_cmp_in_addr_with_mask(
				&(((struct sockaddr_in *) addr)->sin_addr),
				&(((struct sockaddr_in *) cur->if_addrs->addr)->sin_addr),
				&(((struct sockaddr_in *) cur->if_netmask)->sin_addr))
		))
		{
			for(cus = cur->if_addrs; cus->next != NULL; cus = cus->next);; 
			_append_sockaddr_list( &(cus->next), addr, family_size);
			return;			
		}
	}
	
	/* we have a new prefix */
	
	/* allocate memory */
	new = malloc(sizeof(struct src_prefix_list));
	if(new == NULL)
		{ DLOG(MAM_IF_NOISY_DEBUG0, "malloc failed"); return; } 
	memset(new, 0, sizeof(struct src_prefix_list));
	
	/* copy data */
	new->if_name = _muacc_clone_string(if_name);
	new->family = family;
	new->if_flags = if_flags;
	_append_sockaddr_list( &(new->if_addrs), addr, family_size);
	new->if_netmask = _muacc_clone_sockaddr(mask, family_size);
	new->if_netmask_len = family_size;
	
	/* save new one */ 
	*last = new;
	return;
}

int update_src_prefix_list (
	struct src_prefix_list **spfxl
){
    struct ifaddrs *ifaddr, *ifa;
    int family;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return(-1);
    }
	
    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        family = ifa->ifa_addr->sa_family;

        if(ifa->ifa_addr == NULL) {
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
			int s
            s = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	        s = getnameinfo(ifa->mask,
	            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
	            mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
         	DLOG(MAM_IF_NOISY_DEBUG1("scanning for family: %d%s, address: %s mask: %s",
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
    exit(EXIT_SUCCESS);
}

