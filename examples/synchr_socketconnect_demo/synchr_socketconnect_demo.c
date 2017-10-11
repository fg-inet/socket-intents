#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <muacc/client_socketconnect_emulated.h>
#include <muacc/intents.h>

int main(void)
{
	int fd;
	int ret;

	char *host="www.example.com", *port="80";
	ret=muacc_sce_socketconnect(&fd, host, strlen(host), port, strlen(port), NULL, AF_UNSPEC, SOCK_STREAM, 0);

	if(ret==-1) {
		fprintf(stderr, "socketconnect failed.\n");
		return -1;
	}

	printf("socketconnect successful, fd=%i\n", fd);

	/* TODO: Do something with the fd. */

	ret=muacc_sce_socketclose(fd);

	if(ret==-1) {
		fprintf(stderr, "socketclose failed.\n");
		return -1;
	}

	return 0;
}