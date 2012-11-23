#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include "muacc.h"


int main(int c, char **v) {
	
	struct addrinfo hints, *res, *res0;
	int error;
	char pbuf[NI_MAXSERV];
    char abuf[NI_MAXHOST];
	int i = 0;
	
	struct muacc_context ctx; 
	muacc_init_context(&ctx);
	
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
	
	if (c < 2 || c > 3) 
	{
		fprintf(stderr, "usage: %s hostname [service]\n", v[0]);
		exit(1);
	} 
	else if (c == 2) 
	{
	    error = getaddrinfo(v[1], NULL, &hints, &res0);
	} 
	else if (c == 3) 
	{
	    error = getaddrinfo(v[1], v[2], &hints, &res0);
	}

    if (error) {
        errx(1, "%s", gai_strerror(error));
    }
	
    for (res = res0; res; res = res->ai_next) {
	    memset(&abuf, 0, sizeof(abuf));
	    memset(&pbuf, 0, sizeof(pbuf));
		muacc_getnameinfo( &ctx, 
					 res->ai_addr, res->ai_addrlen,
				     abuf, sizeof(abuf)-1, pbuf, sizeof(pbuf),
					 NI_NUMERICHOST|NI_NUMERICSERV);
        fprintf(stderr, "response %2d: %-24s port %-5s\n", i++, abuf, pbuf);	
	}
	
	muacc_release_context(&ctx);
	exit(0);
			   
}
			   