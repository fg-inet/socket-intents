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
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/if_ether.h>


#include "../config.h"

#include "../clib/dlog.h"

#define MAM_IF_NOISY_DEBUG0 1

int
main(int argc, char *argv[])
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
	{
        family = ifa->ifa_addr->sa_family;

        /* Display interface name and family (including symbolic
           form of the latter for the common families) */

        printf("%s  address family: %d%s\n",
                ifa->ifa_name, family,
#ifdef AF_PACKET                        
				(family == AF_PACKET) ? " (AF_PACKET)" :
#elif AF_LINK                        
				(family == AF_LINK) ? " (AF_LINK)" :
#endif
                (family == AF_INET) ?   " (AF_INET)" :
                (family == AF_INET6) ?  " (AF_INET6)" : "");

        /* For an AF_INET* interface address, display the address */
        if (family == AF_INET || family == AF_INET6) 
		{
            s = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            printf("\taddress: %s\n", host);
        }
#if AF_LINK                        
		else if(family == AF_LINK)
		{
		    struct sockaddr_dl *sdl = (struct sockaddr_dl *) ifa->ifa_addr;
			char mac[ETHER_ADDR_LEN];
			memcpy(mac, LLADDR(sdl), ETHER_ADDR_LEN);
			printf("\taddress: %02x:%02x:%02x:%02x:%02x:%02x\n",(unsigned char)mac[0],
			                                                                     (unsigned char)mac[1],
			                                                                     (unsigned char)mac[2],
			                                                                     (unsigned char)mac[3],
			                                                                     (unsigned char)mac[4],
			                                                                     (unsigned char)mac[5]);	
		}
#endif
		
	}

           freeifaddrs(ifaddr);
		   exit(EXIT_SUCCESS);
}

/** get hardware address of a network device
 * this function are plattform depending functions!
 * @return 0 on succsess, -1 otherwise
**/
int _gethwaddr(
	const char *if_name,	/**< [in]  name of the interface to check */
	char *if_hwaddr			/**< [out] hardware address of the interface */
)
#ifdef SIOCGIFHWADDR
{
    /* the linux and solaris way */
    int sockfd;
    struct ifreq ifr;
    
    /* we need some socket to do that */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    /* set interface options and get hardwareaddr */
    strncpy(ifr.ifr_name,if_name,sizeof(ifr.ifr_name));
    
    
    #ifdef SIOCGIFHWADDR
    if ( ioctl(sockfd, SIOCGIFHWADDR, &ifr) >= 0 ) {
        memcpy( if_hwaddr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN );
    /* } */
    #elif defined SIOCGENADDR
    if ( ioctl(sd, SIOCGENADDR, &ifr_work) >= 0 ) {
        memcpy( if_hwaddr, &ifr.ifr_enaddr, ETHER_ADDR_LEN );
    /* } */    
    #else
    if(false) {
    #endif
        close(sockfd);
        return(0);
    } else {
        DLOG(MAM_IF_NOISY_DEBUG0, "aquireing hwaddr faild");
        close(sockfd);
        return(-1);
    }
}
#elif __MACH__
{
    /* the Apple way... */

    int                     mib[6];
    size_t                  len;
    char                    *buf, *next;
    struct if_msghdr        *ifm;
    struct sockaddr_dl      *sdl;
    int ret = -1;
    
    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;
    
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
            DLOG(MAM_IF_NOISY_DEBUG0, "aquireing hwaddr faild: sysctl 1 error");
            return(-1);
    }
    
    if ((buf = malloc(len)) == NULL) {
            DLOG(MAM_IF_NOISY_DEBUG0, "aquireing hwaddr faild: malloc error");
            return(-1);
    }
    
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
            DLOG(MAM_IF_NOISY_DEBUG0, "aquireing hwaddr faild: sysctl 2 error");
            return(-1);
    }
    
    for (next = buf; next < buf+len; next += ifm->ifm_msglen) {
        ifm = (struct if_msghdr *)next;
        if (ifm->ifm_type == RTM_IFINFO) {
            sdl = (struct sockaddr_dl *)(ifm + 1);
            if (strncmp(&sdl->sdl_data[0], if_name, sdl->sdl_len) == 0) {
                memcpy(if_hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
                ret = 0;
                break;
            }
        }
    }
    
    free(buf);
    return ret;
}
#elif __FreeBSD__
{
    struct ifaddrs   *ifaphead;
    struct ifaddrs   *ifap;
    struct sockaddr_dl *sdl = NULL;

    if (getifaddrs(&ifaphead) != 0)
    {
        DLOG(MAM_IF_NOISY_DEBUG0, "getifaddrs() failed");
        return(-1);
    }

    for (ifap = ifaphead; ifap ; ifap = ifap->ifa_next)
    {
        if ((ifap->ifa_addr->sa_family == AF_LINK))
        {
            if (strcmp(ifap->ifa_name,if_name) == 0)
            {
                sdl = (struct sockaddr_dl *)ifap->ifa_addr;
                if (sdl)
                {
                    memcpy(if_hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
                    return(0);
                }
            }
        }
    }
    return(-1);
}

#else
    DLOG(MAM_IF_NOISY_DEBUG0, "aquireing hwaddr faild - platform not supported");
    return(-1);
}
#endif

