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
#include "muacc.h"

/* socks 5 protocol stuff */
#define SOCKS5_AUTHDONE	0x1000
#define SOCKS5_NOAUTH	0x00
#define SOCKS5_IPV4		0x01
#define SOCKS5_DOMAIN	0x03
#define SOCKS5_IPV6		0x04
#define SOCKS5_CONNECT	0x01
#define SOCKS5_SUCCESS	0x00
#define SOCKS5_CUNSUPPORTED	0x07
#define SOCKS5_AUNSUPPORTED	0x08
#define SOCKS5_GFAIL	0x01



void do_socks( int fd, struct sockaddr *remote_in, socklen_t remote_in_len, struct sockaddr *local_in, socklen_t local_in_len)
{
	
    int flags = 0;
	int rlen = 0;
    int i = 0;
    struct sockaddr_storage local_out = {}, remote_out = {};
	char muacc_ctx[255] = {}; 
    
	union socks5_inputbuffer 
	{
		struct
		{
			u_int8_t version;
			u_int8_t nmethods;
			u_int8_t method[255];
		} socks5_auth_req;
		struct
		{
			u_int8_t version;
			u_int8_t method;
		} socks5_auth_resp;
		struct 
		{
			u_int8_t version;
			u_int8_t command;
			u_int8_t reserved;
			u_int8_t atyp;
            union {
				struct {
	                struct in_addr sin_addr;
					u_int16_t port;
				} ipv4;
				struct {
                	struct in6_addr sin6_addr;
					u_int16_t port;
                } ipv6;
				struct {
                    u_int8_t len;
                    u_int8_t fqdn[257];
					/* fqdn+len is port */
                } domain_name;
            } addr;
        } socks5_command;
        u_int8_t raw[1500];
    } socks5_iobuffer __attribute__((__packed__));
	
	/* handle authentication */
	fprintf(stderr, "%6d: waiting for socks5 authentication\n", (int) getpid());
	while( (flags & SOCKS5_AUTHDONE) == 0 )
	{
        /* read request */
		rlen = read(fd, &socks5_iobuffer, sizeof(socks5_iobuffer));
		if (rlen == 0) 
			goto do_socks_closed;
		else if ( rlen < 0 )
			goto do_socks_error;
        else if ( rlen < 3 )
        {
            fprintf(stderr, "%6d: error while handling socks5 authentication: request too small\n", (int) getpid());
            goto do_socks_closed;
        }
        else if ( socks5_iobuffer.socks5_auth_req.version != 0x05 )
        {
            fprintf(stderr, "%6d: error while handling socks5 authentication: wrong protocol version\n", (int) getpid());
            goto do_socks_closed;
        }
        else if ( rlen < socks5_iobuffer.socks5_auth_req.nmethods+2 )
        {
            fprintf(stderr, "%6d: error while handling socks5 authentication: packet too small\n", (int) getpid());
            goto do_socks_closed;
        }
        
        for (i = 0; i < socks5_iobuffer.socks5_auth_req.nmethods; i++)
        {
            if (socks5_iobuffer.socks5_auth_req.method[i] == SOCKS5_NOAUTH)
            {
                flags |= SOCKS5_AUTHDONE;
                socks5_iobuffer.socks5_auth_resp.method = SOCKS5_NOAUTH;
                send(fd, &socks5_iobuffer, 2, 0);
                break;
            }
        }
	}
    fprintf(stderr, "%6d: socks5 authentication done\n", (int) getpid());

    /* parse request */
    rlen = read(fd, &socks5_iobuffer, sizeof(socks5_iobuffer));
    if (rlen == 0)
        goto do_socks_closed;
    else if ( rlen < 0 )
        goto do_socks_error;
    else if ( rlen < 10 )
    {
        fprintf(stderr, "%6d: error while handling socks5 request: request too small\n", (int) getpid());
        goto do_socks_closed;
    }
    else if ( socks5_iobuffer.socks5_command.version != 0x05 )
    {
        fprintf(stderr, "%6d: error while handling socks5 request: wrong protocol version\n", (int) getpid());
        goto do_socks_closed;
    }
    
    /* handle commands */
    if (socks5_iobuffer.socks5_command.command == SOCKS5_CONNECT)
    {
        /* TCP connect request - check address and resolve if needed */
        if (socks5_iobuffer.socks5_command.atyp == SOCKS5_IPV4 &&
			rlen >= 10 )
        {
            /* ipv4 */
            struct sockaddr_in *sin = (struct sockaddr_in *) &remote_out;
            sin->sin_family = AF_INET;
            memcpy(&(sin->sin_addr), &socks5_iobuffer.socks5_command.addr.ipv4.sin_addr, sizeof(struct in_addr));
            sin->sin_port = socks5_iobuffer.socks5_command.addr.ipv4.port;
        }
        else if (socks5_iobuffer.socks5_command.atyp == SOCKS5_IPV6 &&
				 rlen >= 22)
        {
            struct sockaddr_in6 *sin = (struct sockaddr_in6 *) &remote_out;
            sin->sin6_family = AF_INET6;
            memcpy(&(sin->sin6_addr), &socks5_iobuffer.socks5_command.addr.ipv6.sin6_addr, sizeof(struct in6_addr));
            sin->sin6_port = socks5_iobuffer.socks5_command.addr.ipv6.port;
        }
        else if (socks5_iobuffer.socks5_command.atyp == SOCKS5_DOMAIN &&
				 rlen >= (4+1+socks5_iobuffer.socks5_command.addr.domain_name.len+2))
		{

		}
		else
		{
	        fprintf(stderr, "%6d: error while handling socks5 request: request too small for given address type\n", (int) getpid());
	        goto do_socks_closed;	
		}
        
    }
    else
    {
        /* unsupported command */
        fprintf(stderr, "%6d: error while handling socks5 request: insupported command %x\n", (int) getpid(), socks5_iobuffer.socks5_command.command);
        socks5_iobuffer.socks5_command.command = SOCKS5_CUNSUPPORTED;
        socks5_iobuffer.socks5_command.reserved = 0x00;
        send(fd, &socks5_iobuffer, rlen, 0);
        goto do_socks_closed;
    }

    fprintf(stderr, "%6d: this never happens: fell out of the stocks state machine\n", (int) getpid());
    goto do_socks_closed;
    
do_socks_error:
	fprintf(stderr, "%6d: i/o error while handling socks5 request:\n", (int) getpid());
	perror(NULL);
	
do_socks_closed:		
	fprintf(stderr, "%6d: connection closed\n", (int) getpid());
	close(fd);
}

int do_accept(int listener)
{
    struct sockaddr_storage sa = {};
	socklen_t salen = sizeof(sa);	
	struct sockaddr_storage	 la = {};
	socklen_t lalen = sizeof(la); 
    int fd = -1, pid= -1;
    
	/* accept connection */
    if ( (fd = accept(listener, (struct sockaddr*)&sa, &salen)) < 0 ) 
	{
        perror("master: accept error");
		return(-1);
    }
	
	if (getsockname(fd, (struct sockaddr*) &la, &lalen) <0 ) 
	{
        perror("master: getsockname error");
		return(-1);
	};
	
	/* fork child */
	if ( (pid = fork()) < 0 )
	{
	    perror("fork error");
		return(-1);
    }
	else if (pid == 0) 
	{
		/* handle socks in child */
        close(listener);
        do_socks(fd, (struct sockaddr*) &sa, salen, (struct sockaddr*) &la, lalen );
        exit(0);
    }
	else
	{
		/* some debug output in master */
	    char abuf[INET6_ADDRSTRLEN];
		char pbuf[NI_MAXSERV];	
	    getnameinfo( (struct sockaddr*) &sa, salen, abuf, sizeof(abuf)-1, pbuf, sizeof(pbuf)-1, NI_NUMERICHOST|NI_NUMERICSERV);
	    fprintf(stderr, "master: forked %d to handle connection from %s port %s\n", pid, abuf, pbuf);
		
		/* close client fd */
        close(fd);
    }
	
	return(0);
}


int
main(int c, char **v)
{
    struct sockaddr_in6	sin = {};
    int listener = -1;
    int one  = 1;
    int zero = 0;
	int ret = 0;

    char hbuf[NI_MAXHOST];
    char abuf[INET6_ADDRSTRLEN];
    
    setvbuf(stdout, NULL, _IONBF, 0);
    
	/* set up v6 socket */
    sin.sin6_family = AF_INET6;
    sin.sin6_addr = in6addr_any;
    sin.sin6_port = htons(10800);
    listener = socket(AF_INET6, SOCK_STREAM, 0);
    
    setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	
    /* try to bind */
    getnameinfo( (struct sockaddr*) &sin, sizeof(sin), hbuf, sizeof(hbuf)-1, NULL, 0, NI_NOFQDN);
    getnameinfo( (struct sockaddr*) &sin, sizeof(sin), abuf, sizeof(abuf)-1,  NULL, 0, NI_NUMERICHOST);
    fprintf(stderr, "master: trying to bind to %s (%s) port %d: ", abuf, hbuf, ntohs(sin.sin6_port));
    if( bind(listener, (struct sockaddr*) &sin, sizeof(sin)) == 0 ) {
        fprintf(stderr, "ok\n");
    } else {
        perror("errs");
        exit(1);
    }
    
    /* try to listen */
    fprintf(stderr, "master: trying to listen: ");
	if( listen(listener, 16) == 0 ) {
        fprintf(stderr, "ok\n");
    } else {
        perror("err");
        exit(1);
    }
    
    fprintf(stderr, "master: start accepting clients...\n");
    while( (ret = do_accept(listener)) == 0 )
       ;;
    
	return(ret);
}