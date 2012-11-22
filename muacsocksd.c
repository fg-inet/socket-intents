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
    char abuf[INET6_ADDRSTRLEN];
	char pbuf[NI_MAXSERV];
    char nbuf[NI_MAXHOST];
    
	union s5_inputbuffer 
	{
		struct
		{
			u_int8_t version;
			u_int8_t nmethods;
			u_int8_t method[255];
		} auth_req;
		struct
		{
			u_int8_t version;
			u_int8_t method;
		} auth_resp;
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
                    u_int8_t fqdn[255];
					u_int16_t port_pad; /* fqdn+len is real port */
                } domain_name;
            } addr;
        } cmd;
        u_int8_t raw[1500];
    } s5_iobuffer __attribute__((__packed__));
	memset(&s5_iobuffer, 0x0, sizeof(s5_iobuffer));
	
	/* handle authentication */
	fprintf(stderr, "%6d: waiting for authentication\n", (int) getpid());
	while( (flags & SOCKS5_AUTHDONE) == 0 )
	{
        /* read request */
		memset(&s5_iobuffer, 0x0, sizeof(s5_iobuffer));
		rlen = read(fd, &s5_iobuffer, sizeof(s5_iobuffer));
		if (rlen == 0) 
			goto do_socks_closed;
		else if ( rlen < 0 )
			goto do_socks_error;
        else if ( rlen < 3 )
        {
            fprintf(stderr, "%6d: error while handling authentication: request too small\n", (int) getpid());
            goto do_socks_closed;
        }
        else if ( s5_iobuffer.auth_req.version != 0x05 )
        {
            fprintf(stderr, "%6d: error while handling authentication: wrong protocol version\n", (int) getpid());
            goto do_socks_closed;
        }
        else if ( rlen < s5_iobuffer.auth_req.nmethods+2 )
        {
            fprintf(stderr, "%6d: error while handling authentication: packet too small\n", (int) getpid());
            goto do_socks_closed;
        }
        
        for (i = 0; i < s5_iobuffer.auth_req.nmethods; i++)
        {
            if (s5_iobuffer.auth_req.method[i] == SOCKS5_NOAUTH)
            {
                flags |= SOCKS5_AUTHDONE;
                s5_iobuffer.auth_resp.method = SOCKS5_NOAUTH;
                send(fd, &s5_iobuffer, 2, 0);
                break;
            }
        }
	}
    fprintf(stderr, "%6d: authentication done\n", (int) getpid());

    /* parse request */
	memset(&s5_iobuffer, 0x0, sizeof(s5_iobuffer));
    rlen = read(fd, &s5_iobuffer, sizeof(s5_iobuffer));
    if (rlen == 0)
        goto do_socks_closed;
    else if ( rlen < 0 )
        goto do_socks_error;
    else if ( rlen < 10 )
    {
        fprintf(stderr, "%6d: error while handling request: request too small\n", (int) getpid());
        goto do_socks_closed;
    }
    else if ( s5_iobuffer.cmd.version != 0x05 )
    {
        fprintf(stderr, "%6d: error while handling request: wrong protocol version\n", (int) getpid());
        goto do_socks_closed;
    }
    
    /* handle commands */
    if (s5_iobuffer.cmd.command == SOCKS5_CONNECT)
    {
        /* TCP connect request - check address and resolve if needed */
        if (s5_iobuffer.cmd.atyp == SOCKS5_IPV4 &&
			rlen >= 10 )
        {
            /* ipv4 */
            struct sockaddr_in *sin = (struct sockaddr_in *) &remote_out;
			sin->sin_family = AF_INET;
			
            memcpy(&(sin->sin_addr), &s5_iobuffer.cmd.addr.ipv4.sin_addr, sizeof(struct in_addr));
            
			sin->sin_port = s5_iobuffer.cmd.addr.ipv4.port;
			
			getnameinfo( (struct sockaddr*) sin, sizeof(struct sockaddr_in),
					 	 abuf, sizeof(abuf)-1, NULL, 0,
					     NI_NUMERICHOST|NI_NUMERICSERV);
	        fprintf(stderr, "%6d: got connect request (v4) to %s port %d\n", (int) getpid(), abuf, ntohs(sin->sin_port));
			
        }
        else if (s5_iobuffer.cmd.atyp == SOCKS5_IPV6 &&
				 rlen >= 22)
        {
			/* ipv6 */
            struct sockaddr_in6 *sin = (struct sockaddr_in6 *) &remote_out;
            sin->sin6_family = AF_INET6;
			
            memcpy(&(sin->sin6_addr), &s5_iobuffer.cmd.addr.ipv6.sin6_addr, sizeof(struct in6_addr));
            
			sin->sin6_port = s5_iobuffer.cmd.addr.ipv6.port;
			
			getnameinfo( (struct sockaddr*) sin, sizeof(struct sockaddr_in6),
					     abuf, sizeof(abuf)-1, NULL, 0,
						 NI_NUMERICHOST|NI_NUMERICSERV);
	        fprintf(stderr, "%6d: got connect request (v6) to %s port %d\n", (int) getpid(), abuf, ntohs(sin->sin6_port));
        }
        else if (s5_iobuffer.cmd.atyp == SOCKS5_DOMAIN &&
				 rlen >= (4+1+s5_iobuffer.cmd.addr.domain_name.len+2))
		{
			/* fqdn */
            struct sockaddr_in6 *sin = (struct sockaddr_in6 *) &remote_out;
			memset(&nbuf, 0x0, sizeof(nbuf));
			
			/* safely copy over fqdn from request packet */
			assert(NI_MAXHOST > sizeof(s5_iobuffer.cmd.addr.domain_name.fqdn) &&
				   sizeof(s5_iobuffer.cmd.addr.domain_name.fqdn) == 255);
			memcpy(nbuf, 
				   s5_iobuffer.cmd.addr.domain_name.fqdn,
				   s5_iobuffer.cmd.addr.domain_name.len);
			assert(nbuf[s5_iobuffer.cmd.addr.domain_name.len] == 0x00);			
            
			/* peel out port */
            memcpy( &(sin->sin6_port), 
				    s5_iobuffer.cmd.addr.domain_name.fqdn+s5_iobuffer.cmd.addr.domain_name.len,
				    sizeof(sin->sin6_port));

	        fprintf(stderr, "%6d: got connect request (name) to %s port %d\n", (int) getpid(), nbuf, ntohs(sin->sin6_port));
		}
		else
		{
	        fprintf(stderr, "%6d: error while handling request: request too small for given address type\n", (int) getpid());
	        goto do_socks_closed;	
		}
        
    }
    else
    {
        /* unsupported command */
        fprintf(stderr, "%6d: error while handling s5 request: unsupported command %x\n", (int) getpid(), s5_iobuffer.cmd.command);
        s5_iobuffer.cmd.command = SOCKS5_CUNSUPPORTED;
        s5_iobuffer.cmd.reserved = 0x00;
        send(fd, &s5_iobuffer, rlen, 0);
        goto do_socks_closed;
    }

    fprintf(stderr, "%6d: this never happens: fell out of the stocks state machine\n", (int) getpid());
    goto do_socks_closed;
    
do_socks_error:
	fprintf(stderr, "%6d: i/o error while handling s5 request:\n", (int) getpid());
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