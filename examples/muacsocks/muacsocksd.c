/** \file muacsocksd.c
 *
 * \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "clib/muacc_client.h"
#include "config.h"

#undef SOCKSD_NOISY_DEBUG

/* socks 5 protocol stuff */
#define SOCKS5_AUTHDONE	0x1000
#define SOCKS5_NOAUTH	0x00
#define SOCKS5_IPV4		0x01
#define SOCKS5_DOMAIN	0x03
#define SOCKS5_IPV6		0x04
#define SOCKS5_CONNECT	0x01
#define SOCKS5_SUCCESS	0x00
#define SOCKS5_GFAIL	0x01
#define SOCKS5_HOSTUNREACH	0x04
#define SOCKS5_CUNSUPPORTED	0x07
#define SOCKS5_AUNSUPPORTED	0x08

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
} __attribute__((__packed__));


static int s5_replay(int fd, u_int8_t response, const struct sockaddr *addr)
{
	union s5_inputbuffer s5_iobuffer = {{0}};
	int rlen = sizeof(s5_iobuffer);
	int resp = 0;
	
	s5_iobuffer.cmd.version = 0x05;
	s5_iobuffer.cmd.command = response;
	s5_iobuffer.cmd.reserved = 0x00;
	
	if(addr == NULL)
	{
		rlen = 4;
	}
	else if (addr->sa_family == AF_INET)
	{
        struct sockaddr_in *sin = (struct sockaddr_in *) addr;
		sin->sin_family = AF_INET;
		s5_iobuffer.cmd.atyp = SOCKS5_IPV4;
        memcpy(&s5_iobuffer.cmd.addr.ipv4.sin_addr, &(sin->sin_addr), sizeof(struct in_addr));
        s5_iobuffer.cmd.addr.ipv4.port = sin->sin_port;
		rlen = 10;
	} 
	else if (addr->sa_family == AF_INET6)
	{
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *) addr;
        sin->sin6_family = AF_INET6;
		s5_iobuffer.cmd.atyp = SOCKS5_IPV4;
        memcpy(&s5_iobuffer.cmd.addr.ipv6.sin6_addr, &(sin->sin6_addr), sizeof(struct in6_addr));
        s5_iobuffer.cmd.addr.ipv6.port = sin->sin6_port;
		rlen = 22;	
	}
	else
	{
		rlen = 4;
	}
	
	resp = send(fd, &s5_iobuffer, rlen, 0);
	
	if(rlen != resp) 
	{
		fprintf(stderr, "%6d: sending reply failed: ", (int) getpid());
		perror(NULL);
	}
  return resp;
}

static int s2s_forward(int fda, int fdb)
{
	int ret;
	fd_set read_fds;
	char ab_buf[1500];
	char ba_buf[1500];
	size_t ab_size;
	size_t ba_size;
	struct timeval tv;
	
    tv.tv_sec = 5;       /* timeout (secs.) */
    tv.tv_usec = 0;      /* 0 microseconds */
	
	#ifdef SOCKSD_NOISY_DEBUG
	fprintf(stderr, "%6d: entering io loop: ", (int) getpid());
	#endif
	
	for(;;)
	{
		FD_ZERO(&read_fds);
		FD_SET(fda, &read_fds);
		FD_SET(fdb, &read_fds);
		
		ret = select((fda>fdb?fda:fdb)+1, &read_fds, NULL, NULL, &tv);
				
		if ( ret < 0 ) 
		{
			fprintf(stderr, "%6d: error in select: ", (int) getpid());
			perror(NULL);
			return(-1);
		}
		else if (ret == 0)
		{
			#ifdef SOCKSD_NOISY_DEBUG
			fprintf(stderr, ".");
			#endif
		}
		else
		{			
			if(FD_ISSET(fda, &read_fds))
			{
				ab_size = read(fda, ab_buf, sizeof(ab_buf));
				if (ab_size == 0)
				{
					/* socket closed by local */
					#ifdef SOCKSD_NOISY_DEBUG
					fprintf(stderr, "%6d: connection closed by local\n", (int) getpid());
					#endif
					return(fda);
				}
				#ifdef SOCKSD_NOISY_DEBUG				
				fprintf(stderr, ">");
				#endif
				write(fdb, ab_buf, ab_size);
			}
			if(FD_ISSET(fdb, &read_fds))
			{
				ba_size = read(fdb, ba_buf, sizeof(ba_buf));
				if (ba_size == 0)
				{
					/* socket closed by remote */
					#ifdef SOCKSD_NOISY_DEBUG
					fprintf(stderr, "%6d: connection closed by remote\n", (int) getpid());
					#endif
					return(fdb);
				}
				#ifdef SOCKSD_NOISY_DEBUG
				fprintf(stderr, "<");
				#endif
				write(fda, ba_buf, ba_size);
			}
		}
				
	}
	
	return(-1);
	
}

static void do_socks( int fd, struct sockaddr *remote_in, socklen_t remote_in_len, struct sockaddr *local_in, socklen_t local_in_len)
{
	int fd2;
    int flags = 0;
	int rlen = 0;
	int ret = -1;
    int i = 0;
    struct sockaddr_storage local_out;
	struct sockaddr_storage remote_out;
    socklen_t local_out_len = sizeof(struct sockaddr_storage); 
	socklen_t remote_out_len = sizeof(struct sockaddr_storage);
	
    char abuf[INET6_ADDRSTRLEN];
	char pbuf[NI_MAXSERV];
    char nbuf[NI_MAXHOST];
	struct addrinfo ai_hints = {0};
	struct addrinfo *ai_res = NULL;
	union s5_inputbuffer s5_iobuffer;
	
	struct muacc_context fd2_ctx;
	memset(&fd2_ctx, 0, sizeof(struct muacc_context)); 


	memset(&s5_iobuffer, 0x0, sizeof(s5_iobuffer));
	
	/* handle authentication */
	#ifdef SOCKSD_NOISY_DEBUG	
	fprintf(stderr, "%6d: waiting for authentication\n", (int) getpid());
	#endif
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
	#ifdef SOCKSD_NOISY_DEBUG	
    fprintf(stderr, "%6d: authentication done\n", (int) getpid());
	#endif
	
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
			remote_out_len = sizeof(struct sockaddr_in);
			#ifdef HAVE_SOCKADDR_LEN
			sin->sin_len = remote_out_len; 
			#endif
			
			
            memcpy(&(sin->sin_addr), &s5_iobuffer.cmd.addr.ipv4.sin_addr, sizeof(struct in_addr));
            
			sin->sin_port = s5_iobuffer.cmd.addr.ipv4.port;
			
			#ifdef SOCKSD_NOISY_DEBUG
			getnameinfo( (struct sockaddr*) sin, sizeof(struct sockaddr_in),
					 	 abuf, sizeof(abuf)-1, NULL, 0,
					     NI_NUMERICHOST|NI_NUMERICSERV);
	        fprintf(stderr, "%6d: got connect request (v4) to %s port %d\n", (int) getpid(), abuf, ntohs(sin->sin_port));
			#endif
			
        }
        else if (s5_iobuffer.cmd.atyp == SOCKS5_IPV6 &&
				 rlen >= 22)
        {
			/* ipv6 */
            struct sockaddr_in6 *sin = (struct sockaddr_in6 *) &remote_out;
            sin->sin6_family = AF_INET6;
			remote_out_len = sizeof(struct sockaddr_in6);
			#ifdef HAVE_SOCKADDR_LEN
			sin->sin6_len = remote_out_len; 
			#endif
			
            memcpy(&(sin->sin6_addr), &s5_iobuffer.cmd.addr.ipv6.sin6_addr, sizeof(struct in6_addr));
            
			sin->sin6_port = s5_iobuffer.cmd.addr.ipv6.port;
			
			#ifdef SOCKSD_NOISY_DEBUG
			getnameinfo( (struct sockaddr*) sin, sizeof(struct sockaddr_in6),
					     abuf, sizeof(abuf)-1, NULL, 0,
						 NI_NUMERICHOST|NI_NUMERICSERV);
	        fprintf(stderr, "%6d: got connect request (v6) to %s port %d\n", (int) getpid(), abuf, ntohs(sin->sin6_port));
			#endif
        }
        else if (s5_iobuffer.cmd.atyp == SOCKS5_DOMAIN &&
				 rlen >= (4+1+s5_iobuffer.cmd.addr.domain_name.len+2))
		{
			/* fqdn */
			struct sockaddr_in6 *sin;
			memset(&nbuf, 0x0, sizeof(nbuf));
			in_port_t port;
			
			/* safely copy over fqdn from request packet */
			assert(NI_MAXHOST > sizeof(s5_iobuffer.cmd.addr.domain_name.fqdn) &&
				   sizeof(s5_iobuffer.cmd.addr.domain_name.fqdn) == 255);
			memcpy(nbuf, 
				   s5_iobuffer.cmd.addr.domain_name.fqdn,
				   s5_iobuffer.cmd.addr.domain_name.len);
			assert(nbuf[s5_iobuffer.cmd.addr.domain_name.len] == 0x00);			
            
			/* peel out port */
            memcpy( &(port), 
				    s5_iobuffer.cmd.addr.domain_name.fqdn+s5_iobuffer.cmd.addr.domain_name.len,
				    sizeof(uint16_t));
			
			#ifdef SOCKSD_NOISY_DEBUG
	     	fprintf(stderr, "%6d: got connect request (name) to %s port %d\n", (int) getpid(), nbuf, ntohs(port));
			#endif
			
			/* resolve */
			ai_hints.ai_family = PF_UNSPEC;
			ai_hints.ai_socktype = SOCK_STREAM;
			ret = muacc_getaddrinfo(&fd2_ctx, nbuf, NULL, &ai_hints, &ai_res);
		    if (ret) {
		        fprintf(stderr, "%6d: resolve error: %s\n", (int) getpid(), gai_strerror(ret));
		        s5_iobuffer.cmd.command = SOCKS5_HOSTUNREACH;
		        s5_iobuffer.cmd.reserved = 0x00;
		        send(fd, &s5_iobuffer, rlen, 0);
		        goto do_socks_closed;
		    }
			
			/* put result together */
			memcpy(&remote_out, ai_res->ai_addr, ai_res->ai_addrlen);
			remote_out_len = ai_res->ai_addrlen;
			sin = (struct sockaddr_in6 *) &remote_out;			
			memcpy(&(sin->sin6_port), &port, sizeof(in_port_t));
			
			#ifdef SOCKSD_NOISY_DEBUG
			getnameinfo( (struct sockaddr*) &remote_out, remote_out_len,
					     abuf, sizeof(abuf)-1, pbuf, sizeof(pbuf),
						 NI_NUMERICHOST|NI_NUMERICSERV);
			fprintf(stderr, "%6d: resolved %s to %s port %s\n",(int) getpid(), nbuf, abuf, pbuf);
			#endif
			
		}
		else
		{
	        fprintf(stderr, "%6d: error while handling request: request too small for given address type\n", (int) getpid());
	        goto do_socks_closed;	
		}
		
		/* create socket */
		fd2 = muacc_socket(&fd2_ctx, remote_out.ss_family, SOCK_STREAM, 0);
		if (fd2 <= 0)
		{
			fprintf(stderr, "%6d: error creating socket: ", (int) getpid());
			perror(NULL);
			s5_replay(fd, SOCKS5_GFAIL, NULL);
	        goto do_socks_closed;
		}
		else
		{
			#ifdef SOCKSD_NOISY_DEBUG
			fprintf(stderr, "%6d: remote socket created successfully\n", (int) getpid());
			#endif
		}
		
		/* go ahead an connect */
		ret = muacc_connect(&fd2_ctx, fd2, (struct sockaddr *) &remote_out, remote_out_len);
	 	if (ret == 0) 
		{
			#ifdef SOCKSD_NOISY_DEBUG
			getnameinfo( (struct sockaddr*) &remote_out, sizeof(remote_out),
					     abuf, sizeof(abuf)-1, pbuf, sizeof(pbuf)-1, 
						 NI_NUMERICHOST|NI_NUMERICSERV);
			fprintf(stderr, "%6d: connect successful - remote host af %d host %s port %s\n", (int) getpid(), remote_out.ss_family, abuf, pbuf);	
			#endif
		}
		else
		{
			getnameinfo( (struct sockaddr*) &remote_out, sizeof(remote_out),
					     abuf, sizeof(abuf)-1, pbuf, sizeof(pbuf)-1, 
						 NI_NUMERICHOST|NI_NUMERICSERV);
			fprintf(stderr, "%6d: error while connecting to remote host af %d host %s port %s: ", (int) getpid(), remote_out.ss_family, abuf, pbuf); 
			perror(NULL);
			s5_replay(fd, SOCKS5_HOSTUNREACH, NULL);
	        goto do_socks_closed;
		}
		
		/* get local end */
		memset(&local_out, 0x00, sizeof(local_out));
		ret = getsockname(fd2, (struct sockaddr *) &local_out, &local_out_len);
	  	if ( ret != 0 ) 
		{
			fprintf(stderr, "%6d: error getting local address while connecting to remote host: ", (int) getpid()); 
			perror(NULL);
			s5_replay(fd, SOCKS5_GFAIL, NULL);
	        goto do_socks_closed;
		}
		
		/* print debug info */
		#ifdef SOCKSD_NOISY_DEBUG
		ret = getnameinfo( (struct sockaddr*) &local_out, sizeof(local_out),
				     abuf, sizeof(abuf)-1, pbuf, sizeof(pbuf)-1, 
					 NI_NUMERICHOST|NI_NUMERICSERV);
		if (ret == 0) 
		{
    		fprintf(stderr, "%6d: connect successful - local end is %s port %s\n", (int) getpid(), abuf, pbuf);
		} 
		else
		{
			fprintf(stderr, "%6d: connect ambiguous - failed to get local address: %s af %d\n", (int) getpid(), gai_strerror(ret), local_out.ss_family);
			exit(1);
		}
		#endif
		
		/* send ok */
		s5_replay(fd, SOCKS5_SUCCESS, (struct sockaddr *) &local_out);

		/* forward stuff */
		s2s_forward(fd, fd2);
		muacc_close(&fd2_ctx, fd2);
        goto do_socks_closed;
        
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
	#ifdef SOCKSD_NOISY_DEBUG		
	fprintf(stderr, "%6d: connection closed\n", (int) getpid());
	#endif
	close(fd);
}

static int do_accept(int listener)
{
    struct sockaddr_storage sa = {0};
	socklen_t salen = sizeof(sa);	
	struct sockaddr_storage	 la = {0};
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
        #ifdef SOCKSD_NOISY_DEBUG
	    char abuf[INET6_ADDRSTRLEN];
		char pbuf[NI_MAXSERV];	
        #endif
		
		#ifdef SOCKSD_NOISY_DEBUG
	    getnameinfo( (struct sockaddr*) &sa, salen, abuf, sizeof(abuf)-1, pbuf, sizeof(pbuf)-1, NI_NUMERICHOST|NI_NUMERICSERV);
	    fprintf(stderr, "master: forked %d to handle connection from %s port %s\n", pid, abuf, pbuf);
		#endif
		
		/* close client fd */
        close(fd);
    }
	
	return(0);
}


int
main(int c, char **v)
{
    struct sockaddr_in6	sin = {0};
    int listener = -1;
    int one  = 1;
    int zero = 0;
	int ret = 0;

    /* some debug output in master */
    #ifdef SOCKSD_NOISY_DEBUG
    char hbuf[NI_MAXHOST];
    char abuf[INET6_ADDRSTRLEN];
    #endif
    
    setvbuf(stderr, NULL, _IONBF, 0);
    
	/* set up v6 socket */
    sin.sin6_family = AF_INET6;
	#ifdef HAVE_SOCKADDR_LEN
	sin.sin6_len = sizeof(sin);
	#endif
    sin.sin6_addr = in6addr_any;
    sin.sin6_port = htons(9050);

    listener = socket(AF_INET6, SOCK_STREAM, 0);
    
    setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	
	#ifdef SOCKSD_NOISY_DEBUG
    getnameinfo( (struct sockaddr*) &sin, sizeof(sin), hbuf, sizeof(hbuf)-1, NULL, 0, NI_NOFQDN);
    getnameinfo( (struct sockaddr*) &sin, sizeof(sin), abuf, sizeof(abuf)-1,  NULL, 0, NI_NUMERICHOST);
    fprintf(stderr, "master: trying to bind to %s (%s) port %d: ", abuf, hbuf, ntohs(sin.sin6_port));
    #endif
    
	/* try to bind */
	if( bind(listener, (struct sockaddr*) &sin, sizeof(sin)) == 0 ) {
        fprintf(stderr, "ok\n");
    } else {
        perror("errs");
        exit(1);
    }
    
    /* try to listen */

	#ifdef SOCKSD_NOISY_DEBUG
	fprintf(stderr, "master: trying to listen: ");
	#endif
	if( listen(listener, 16) == 0 ) {
		#ifdef SOCKSD_NOISY_DEBUG
        fprintf(stderr, "ok\n");
		#endif
    } else {
        perror("failed to listen");
        exit(1);
    }
    
	#ifdef SOCKSD_NOISY_DEBUG
    fprintf(stderr, "master: start accepting clients...\n");
	#endif
    while( (ret = do_accept(listener)) == 0 )
       ;;
    
	return(ret);
}
