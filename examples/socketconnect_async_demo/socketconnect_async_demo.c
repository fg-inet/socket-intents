#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>

#include <muacc/client_socketconnect.h>
#include <muacc/client_socketconnect_async.h>
#include <muacc/intents.h>

static int(*custom_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = NULL;
static int(*custom_socketconnect)(int *s, const char *host, size_t hostlen, const char *serv, size_t servlen, struct socketopt *sockopts, int domain, int type, int proto) = NULL;
static int(*custom_socketclose)(int s) = NULL;


struct my_connection {
	int delay_ms;
	char *hostname;
	char *service;
	char  *path;
	intent_category_t intent_category; // Possible values: INTENT_QUERY, INTENT_BULKTRANSFER, INTENT_CONTROLTRAFFIC, INTENT_KEEPALIVES, INTENT_STREAM
	enum {
		NOT_CONNECTED=0, CONNECT_CALLED, QUERY_SENT, FINISHED
	} state;
	int fd;
	int socketconnect_blocked_ms;
	size_t recv_nbytes_total;
} connections[] = {
	{400, "www.example.com", "80", "/", INTENT_QUERY, 0, 0, 0, 0},
	{450, "www.inet.tu-berlin.de", "80", "/", INTENT_BULKTRANSFER, 0, 0, 0, 0},
	{450, "ietf.org", "80", "/", INTENT_BULKTRANSFER, 0, 0, 0, 0}
};



int64_t timeval_to_ms(struct timeval *timeval) {
	int64_t sec=timeval->tv_sec;
	int64_t usec=timeval->tv_usec;
	return usec/1000 + sec*1000;
}

void ms_to_timeval(struct timeval *timeval, int64_t ms) {
	timeval->tv_sec=ms/1000;
	timeval->tv_usec=(ms%1000)*1000;
}

int64_t ms_now(void) {
	struct timeval now;
	gettimeofday(&now, NULL);
	return timeval_to_ms(&now);
}

static inline void set_color(struct my_connection *conn) {
	printf("\x1B[3%lim", ((conn-connections)%8)+1);
	fflush(stdout);
}

static inline void clear_color(void) {
	printf("\x1B[0m");
	fflush(stdout);
}


void do_connect(struct my_connection *conn) {
	set_color(conn);
 	struct socketopt *socketopt_list=NULL; // Ueber diese Liste koennen Intents mitgegeben werden?
   
   	muacc_set_intent(&socketopt_list, INTENT_CATEGORY, &conn->intent_category, sizeof(intent_category_t), 0);
   
	printf("Connection #%ti: Calling socketconnect...\n", conn-connections);

	conn->fd=-1; // no socket reuse -- that is not implemented yet!

	int64_t start=ms_now();
    int ret=custom_socketconnect(
    	&conn->fd,
    	conn->hostname, strlen(conn->hostname),
    	conn->service, strlen(conn->service),
    	socketopt_list,
    	AF_UNSPEC, SOCK_STREAM, 0);
	int64_t end=ms_now();
	conn->socketconnect_blocked_ms=(int)(end - start);
	
    if(ret<0) {
        printf("Error creating socket");
        clear_color();
        exit(1);
    }

	printf("Connection #%ti: socketconnect returned %i (%s) after %i ms, socket_fd=%i\n",
        conn-connections, ret, ret==1?"created":ret==0?"reused":ret==-1?"failure":"??", conn->socketconnect_blocked_ms, conn->fd);

	muacc_free_socket_option_list(socketopt_list);
	socketopt_list=NULL;
	clear_color();
}

void send_query(struct my_connection *conn) {
	set_color(conn);
	
	char buf[1024];
	size_t len=snprintf(buf, 1024,
		"GET %s HTTP/1.0\n"
		"Host: %s\n"
		"\n",
		conn->path, conn->hostname);
	
	if(len<0) {
		fprintf(stderr, "snprintf failed\n");
		clear_color();
		exit(1);
	} 
	
	size_t bytes_written=write(conn->fd, buf, len);
	if(bytes_written!=len) {
		fprintf(stderr, "write failed\n");
		clear_color();
		exit(1);
	}
	
	printf("Connection #%ti: Query (%zi bytes) sent.\n", conn-connections, bytes_written);
	
	clear_color();
}

void remove_control_characters(char *buf, size_t len) {
	int i;
	const static char *printable="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
	for(i=0;i<len;i++) {
		if(strchr(printable, buf[i])==NULL) {
			buf[i]='.';
		}
	}
}

bool read_response(struct my_connection *conn) { // returns true if EOF reached
	set_color(conn);
	
	char buf[1024+1];
	
	size_t bytes_read=read(conn->fd, buf, 1024);
	
	if(bytes_read==0) { // means end of file
		if(custom_socketclose(conn->fd)<0) {
			printf("Warning: custom_socketclose failed.\n");
		}
		printf("Connection #%ti: Connection closed.\n", conn-connections);
		clear_color();
		return true;
	}
	
	buf[bytes_read]='\0';
	
	remove_control_characters(buf, bytes_read);
	// truncate output
	strcpy(buf+20, "...");
	
	printf("Connection #%ti: Received %zi data bytes: %s\n", conn-connections, bytes_read, buf);
	conn->recv_nbytes_total+=bytes_read;
	
	clear_color();
	return false; // end of file not reached yet
}

void usage(void) {
	fprintf(stderr, "Usage: select_test VARIANT\n"
        "VARIANT can be sc (for client_socketconnect) or sca (for client_socketconnect_async)\n");
}

int main(int argc, char *argv[]) {
    if(argc!=2) {
        usage();
        return 1;
    }

   	if(strcmp(argv[1], "sc")==0) {
   		custom_socketconnect=muacc_sc_socketconnect;
   		custom_select=select;
		custom_socketclose=muacc_sc_socketclose;
   	} else if(strcmp(argv[1], "sca")==0) {
   		custom_socketconnect=muacc_sca_socketconnect;
   		custom_select=muacc_sca_socketselect;
		custom_socketclose=muacc_sca_socketclose;
   	} else {
   		usage();
   		return 1;
   	}

	bool all_connections_finished;
	
	struct my_connection *conn;
	
	int64_t ms_start=ms_now();
	
	do {
		fd_set r_fds, w_fds, x_fds;
		int64_t ms_timeout, my_timeout, now;
		bool timeout_set=false;
		
		FD_ZERO(&r_fds);
		FD_ZERO(&w_fds);
		FD_ZERO(&x_fds);
		
		now=ms_now();
		for(conn=connections;conn<connections+sizeof(connections)/sizeof(struct my_connection);conn++) {
			switch(conn->state) {
				case NOT_CONNECTED:
					// Timeout for delay
					my_timeout = ms_start + conn->delay_ms - now;
					if(!timeout_set || my_timeout<ms_timeout) {
						timeout_set=true;
						ms_timeout=my_timeout;
					}
					break;
				case CONNECT_CALLED:
					// Wait until we can write
					FD_SET(conn->fd, &w_fds); 
					break;
				case QUERY_SENT:
					// After writing comes reading
					FD_SET(conn->fd, &r_fds);
					break;
				case FINISHED:
					break;
			}
		}
		
		struct timeval tv_timeout;
		if(ms_timeout<0)
			ms_timeout=0;
		if(timeout_set)
			ms_to_timeval(&tv_timeout, ms_timeout);
		
		custom_select(FD_SETSIZE, &r_fds, &w_fds, &x_fds, timeout_set?&tv_timeout:NULL);
		
		now=ms_now();
		all_connections_finished=true; // Will be set to false in the following for loop if any connection is not finished yet
		for(conn=connections;conn<connections+sizeof(connections)/sizeof(struct my_connection);conn++) {
			switch(conn->state) {
				case NOT_CONNECTED:
					if(ms_start + conn->delay_ms - now <= 0) {
						do_connect(conn);
						conn->state=CONNECT_CALLED;
					}
					all_connections_finished=false;
					break;
				case CONNECT_CALLED:
					if(FD_ISSET(conn->fd, &w_fds)) {
						send_query(conn);
						conn->state=QUERY_SENT;
					}
					all_connections_finished=false;
					break;
				case QUERY_SENT:
					if(FD_ISSET(conn->fd, &r_fds)) {
						bool finished=read_response(conn);
						if(finished)
							conn->state=FINISHED;
						else
							all_connections_finished=false;
					} else {
						all_connections_finished=false;
					}
					break;
				case FINISHED:
					break;
			}
		}
	} while(!all_connections_finished);

	// Print summary
	printf(
		"Summary\n"
		"-------\n"
	);
	for(conn=connections;conn<connections+sizeof(connections)/sizeof(struct my_connection);conn++) {
		printf("socketconnect to %s:%s%s blocked for %i ms, socket received %zi bytes.\n",
			conn->hostname,
			conn->service,
			conn->path,
			conn->socketconnect_blocked_ms,
			conn->recv_nbytes_total
		);
	}
	return 0;
}
