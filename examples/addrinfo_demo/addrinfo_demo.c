#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <muacc/client_addrinfo.h>
#include <muacc/intents.h>

void send_query(int fd, char *hostname, char *path) {
	
	char buf[1024];
	size_t len=snprintf(buf, 1024,
		"GET %s HTTP/1.0\n"
		"Hostname: %s\n"
		"\n",
		path, hostname);
	
	if(len<0) {
		fprintf(stderr, "snprintf failed\n");
		exit(1);
	} 
	
	size_t bytes_written=write(fd, buf, len);
	if(bytes_written!=len) {
		fprintf(stderr, "write failed\n");
		exit(1);
	}
	
	printf("Query (%zi bytes) sent.\n", bytes_written);
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

bool read_response(int fd) { // returns true if EOF reached
	char buf[1024+1];
	
	size_t bytes_read=read(fd, buf, 1024);
	
	if(bytes_read==0) { // means end of file
		printf("EOF reached.\n");
		return true;
	}
	
	buf[bytes_read]='\0';
	
	remove_control_characters(buf, bytes_read);
	// truncate output
	strcpy(buf+20, "...");
	
	printf("Received %zi data bytes: %s\n", bytes_read, buf);

	return false; // end of file not reached yet
}


void muacc_ai_printai(struct muacc_addrinfo *ai)
{
	struct muacc_addrinfo* cur;
	int number_of_addrinfos, cur_elem_no;
	int error;

	/* Count number of returned muacc_addrinfos: */
	number_of_addrinfos=0;
	for(cur=ai;cur!=NULL;cur=cur->ai_next)
		number_of_addrinfos++;

	printf("muacc_addrinfo list consists of %i muacc_addrinfos.\n", number_of_addrinfos);

	/* loop over all returned results and do inverse lookup */
	cur_elem_no=0;
    for (cur = ai; cur != NULL; cur = cur->ai_next) {
    	cur_elem_no++; 
        char addr[NI_MAXHOST], bindaddr[NI_MAXHOST];
        error = getnameinfo(cur->ai_addr, cur->ai_addrlen, addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST); 
        if (error != 0) {
            fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
            continue;
        }
        error = getnameinfo(cur->ai_bindaddr, cur->ai_bindaddrlen, bindaddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST); 
        if (error != 0) {
            fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
            continue;
        }
        
        printf("(muacc_addrinfo #%i).ai_addr: %s\n", cur_elem_no, addr);
        printf("(muacc_addrinfo #%i).ai_bindaddr: %s\n", cur_elem_no, bindaddr);
    }
}

void usage(void) {
	fprintf(stderr,
		"Usage: addrinfo_demo [OPTIONS] HOSTNAME\n"
		"Options for setting Socket Intents:\n"
		"\t-C (QUERY|BULKTRANSFER|CONTROLTRAFFIC|KEEPALIVES|STREAM) - Set intent category\n"
//		"\t-B (RANDOMBURSTS|REGULARBURSTS|NOBURSTS|BULK) - Set intent burstiness\n"
//		"\t-T (STREAMING|INTERACTIVE|TRANSFER|BACKGROUNDTRAFFIC) - Set intent timeliness\n"
//		"\t-R (SENSITIVE|TOLERANT|RESILIENT) - Set intent resilience\n"
		"\n"
		"Other options:\n"
		"\t-n - Exit after muacc_ai_getaddrinfo and do not attempt to connect.\n"
		"\n"
	);
}

static void set_hint(struct muacc_addrinfo *hints, char c, char *val) {
	int intent_name=-1;
	int intent_value=0;
	switch(c) {
	case 'C':
		intent_name=INTENT_CATEGORY;
		if(strcmp(val, "QUERY")==0) {
			intent_value=INTENT_QUERY;
		} else if(strcmp(val, "BULKTRANSFER")==0) {
			intent_value=INTENT_BULKTRANSFER;
		} else if(strcmp(val, "CONTROLTRAFFIC")==0) {
			intent_value=INTENT_CONTROLTRAFFIC;
		} else if(strcmp(val, "KEEPALIVES")==0) {
			intent_value=INTENT_KEEPALIVES;
		} else if(strcmp(val, "STREAM")==0) {
			intent_value=INTENT_STREAM;
		} else {
			fprintf(stderr, "Error: Unknown intent value!\n");
			exit(1);
		}
		break;
	default:
		fprintf(stderr, "Error: Unknown intent name!\n");
		exit(1);
		return;
	}
	muacc_set_intent(&hints->ai_sockopts, intent_name, &intent_value, sizeof(int), 0);
   
}

int main(int argc, char *argv[]) {
    int error;
    bool just_resolve=false;
    struct muacc_addrinfo hints;
    memset(&hints, 0, sizeof(struct muacc_addrinfo));

	/***************************************************************************
     * Step 1: Read command line arguments.
     **************************************************************************/
    char c;

	while ((c = getopt (argc, argv, "C:B:T:R:n")) != -1)
    switch (c)
	{
	case 'n':
		just_resolve=true;
		break;
	
	case 'C':
	//case 'B':
	//case 'T':
	//case 'R':
		set_hint(&hints, c, optarg);
		break;

	case '?':
		fprintf(stderr,"Unkown command line option received.\n");
		usage();
		return 1;
	default:
		abort ();
	}

	if(optind+1!=argc) {
		fprintf(stderr, "Too many or too few args.\n");
		usage();
		return 1;
	}

    char *hostname=argv[optind];
    
    /***************************************************************************
     * Step 2: Do the getaddrinfo and simple_connect.
     **************************************************************************/
    struct muacc_addrinfo *result;
    
    /* resolve the domain name into a list of addresses */
    error = muacc_ai_getaddrinfo(hostname, "80", &hints, &result);
    if (error != 0) {
        if (error == EAI_SYSTEM) {
            perror("getaddrinfo");
        } else {
            fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
        }   
        exit(EXIT_FAILURE);
    }   

  	muacc_ai_printai(result);  

  	if(just_resolve) {
  		muacc_ai_freeaddrinfo(result);
  		return 0;
  	}

  	int fd;

  	fd=socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    muacc_ai_simple_connect(fd, result);

    muacc_ai_freeaddrinfo(result);

    /***************************************************************************
     * Step 2: Send a HTTP request, receive the response, and close socket.
     **************************************************************************/

    send_query(fd, hostname, "/");

    while(!read_response(fd));

    if(close(fd)<0) {
		printf("Warning: close failed.\n");
		return 1;
	}

    return 0;
}
