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

/* socks 5 protocol stuff */
#define SSH_SOCKS5_AUTHDONE	0x1000
#define SSH_SOCKS5_NOAUTH	0x00
#define SSH_SOCKS5_IPV4		0x01
#define SSH_SOCKS5_DOMAIN	0x03
#define SSH_SOCKS5_IPV6		0x04
#define SSH_SOCKS5_CONNECT	0x01
#define SSH_SOCKS5_SUCCESS	0x00

typedef struct {
	u_int8_t version;
	u_int8_t command;
	u_int8_t reserved;
	u_int8_t atyp;
} s5_rr_t;


void do_run( int fd, struct sockaddr_storage *sa, socklen_t salen)
{
    char hbuf[NI_MAXHOST];
    char abuf[INET6_ADDRSTRLEN];
    
    getnameinfo( (struct sockaddr*) sa, salen, hbuf, sizeof(hbuf)-1, NULL, 0, NI_NOFQDN);
    getnameinfo( (struct sockaddr*) sa, salen, abuf, sizeof(abuf)-1, NULL, 0, NI_NUMERICHOST);
    fprintf(stderr, "accepted connection from %s (%s) port %d: ", abuf, hbuf, ntohs( ((struct sockaddr_in6*) sin).sin_port));
    close(fd);
}

int do_accept(int listener)
{
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    int fd, pid;
    
    if ( (fd = accept(listener, (struct sockaddr*)&sa, &salen)) < 0 ) {
        perror("accept error");
    } else if ( (pid = fork()) < 0 ) {
	    perror("fork error");
    } else if (pid == 0) {
        close(listener);
        do_run(fd, sa, salen);
        exit(0);
    } else {
        close(fd);
    }
}


int
main(int c, char **v)
{
    struct sockaddr_in6	sin;
    struct event_base *base;
    int listener;
    int one  = 1;
    int zero = 0;

    char hbuf[NI_MAXHOST];
    char abuf[INET6_ADDRSTRLEN];
    
    setvbuf(stdout, NULL, _IONBF, 0);
    
	/* set up v6 socket */
    sin.sin_family = AF_INET6;
    sin.sin_addr.s_addr = htonl(in6addr_any);
    sin.sin_port = htons(10800);
    listener = socket(AF_INET6, SOCK_STREAM, 0);
    
    setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	
    /* try to bind */
    getnameinfo(&sin, sizeof(sin), hbuf, sizeof(hbuf)-1, NULL, 0, NI_NOFQDN);
    getnameinfo(&sin, sizeof(sin), abuf, sizeof(abuf)-1,  NULL, 0, NI_NUMERICHOST);
    fprintf(stderr, "trying to bind to %s (%s) port %d: ", abuf, hbuf, ntohs(sin.sin_port));
    if( bind(listener, sin, sizeof(sin) == 0 ) {
        fprintf(stderr, "ok\n");
    } else {
        perror();
        exit(1);
    }
    
    /* try to listen */
    fprintf(stderr, "trying to listen: ");
	if( listen(listener, 16) == 0 ) {
        fprintf(stderr, "ok\n");
    } else {
        perror();
        exit(1);
    }
    
    fprintf(stderr, "start accepting clients...\n");
    while( do_accept(listener) == 0 )
       ;;
    
 
}