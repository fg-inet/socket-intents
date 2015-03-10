/** \file ifaceinfo.c
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


#include "../config.h"

#include "../clib/dlog.h"

#define MAM_IF_NOISY_DEBUG0 1

int
main(int argc, char *argv[])
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    char *lastif = "";

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if(strcmp(lastif, ifa->ifa_name) != 0)
        {
            printf("%s:\n");
            lastif = ifa->ifa_name;
        }

        if(ifa->ifa_addr == NULL) {
            printf("\taddress family: (NULL) - slipping\n");
            continue;
        }

        family = ifa->ifa_addr->sa_family;
        /* Display interface name and family (including symbolic
           form of the latter for the common families) */
        printf("\taddress family: %d%s",
                family,
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
            printf("address: %s\n", host);
        }
#ifdef AF_PACKET
        else if(family == AF_PACKET)
        {
            struct sockaddr_ll *sll = (struct sockaddr_ll *) ifa->ifa_addr;

            char mac[(size_t) sll->sll_halen];
            memcpy(mac, (void *) &(sll->sll_addr), (size_t) (sll->sll_halen));
            printf("address: %02x:%02x:%02x:%02x:%02x:%02x\n",(unsigned char)mac[0],
                                                                                 (unsigned char)mac[1],
                                                                                 (unsigned char)mac[2],
                                                                                 (unsigned char)mac[3],
                                                                                 (unsigned char)mac[4],
                                                                                 (unsigned char)mac[5]);    
        }
#endif
#ifdef AF_LINK
        else if(family == AF_LINK)
        {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *) ifa->ifa_addr;
            char mac[ETHER_ADDR_LEN];
            memcpy(mac, LLADDR(sdl), ETHER_ADDR_LEN);
            printf("address: %02x:%02x:%02x:%02x:%02x:%02x\n",(unsigned char)mac[0],
                                                                                 (unsigned char)mac[1],
                                                                                 (unsigned char)mac[2],
                                                                                 (unsigned char)mac[3],
                                                                                 (unsigned char)mac[4],
                                                                                 (unsigned char)mac[5]);    
        }
#endif
        else
        {
            printf("\n");
        }
    }

    freeifaddrs(ifaddr);
    exit(EXIT_SUCCESS);
}

