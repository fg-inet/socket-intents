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
#include "../clib/muacc.h"
#include "../config.h"



int main(int c, char **v) {
	
	struct addrinfo hints, *res, *res0;
	int error;
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
	    error = muacc_getaddrinfo(&ctx, v[1], NULL, &hints, &res0);
	} 
	else if (c == 3) 
	{
	    error = muacc_getaddrinfo(&ctx, v[1], v[2], &hints, &res0);
	}

    if (error) {
        errx(1, "%s", gai_strerror(error));
    }
	
    for (res = res0; res; res = res->ai_next) {
	    memset(&abuf, 0, sizeof(abuf));
		getnameinfo( res->ai_addr, res->ai_addrlen,
				     abuf, sizeof(abuf)-1, NULL, 0,
					 NI_NUMERICHOST);
        fprintf(stderr, "response %2d: %-24s canonname %-24s\n", i++, abuf, (res->ai_canonname==NULL)?"(none)":(res->ai_canonname));	
	}
	
	freeaddrinfo(res0);
	muacc_release_context(&ctx);
	exit(0);
			   
}
			   