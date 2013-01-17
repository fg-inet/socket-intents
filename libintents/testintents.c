/* 
 * Application to test the Intents socket library extension
 * Run with LD_PRELOAD=libintents.so
 * 
 * Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

/*#include "libintents.h"*/

int main(int argc, char *argv[])
	/* 
	 * Create a socket and set some options
	 */
{
	struct sockaddr testaddr;
	int testsocket;

	printf("Creating socket\n");
	if ((testsocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		perror("socket error");
	
	memset(&testaddr, 0, sizeof(testaddr));
	testaddr.sa_family = AF_INET;
	strncpy(testaddr.sa_data,"127.0.0.1",sizeof(testaddr.sa_data));
	
	int flag = 1;
	if (setsockopt(testsocket, SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag)) < 0)
		perror("error calling setsockopt");


	printf("This is a test routine. There is nothing to see here.\n");
	return 0;

}
