/* 
 * Application to test the Intents socket library extension
 * Run with LD_PRELOAD=./libintents.so.1.0 ./testintents
 * 
 * Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "libintents.h"

int main(int argc, char *argv[])
	/* 
	 * Create a socket and set some options
	 */
{
	struct sockaddr testaddr;
	int testsocket;

	if ((testsocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		perror("Socket error");
	
	memset(&testaddr, 0, sizeof(testaddr));
	testaddr.sa_family = AF_INET;
	strncpy(testaddr.sa_data,"127.0.0.1",sizeof(testaddr.sa_data));
	
	int option = 0;
	int value = 0;
	int level = SOL_INTENTS;
	socklen_t valuesize = sizeof(value);

	if (argc >= 2)
	{
		option = atoi(argv[1]);
	}
	if (argc >= 3)
	{
		value = atoi(argv[2]);
	}
	if (argc >= 4)
	{
		level = atoi(argv[3]);
	}
	printf("Setting/getting option %d value %d on level %d. \n", option, value, level);
	/*
	printf("Working example: %d %d %d \n", SO_BROADCAST, 1, SOL_SOCKET); // 6 1 1
	*/

	printf("\n== Setsockopt test ==\n");
	if (setsockopt(testsocket, level, option, &value, sizeof(value)) < 0)
		perror("Error calling setsockopt");
	else
		printf("Set socket option intent: %d\n", value);
	
	printf("\n== Getsockopt test ==\n");
	if (getsockopt(testsocket, level, option, &value, &valuesize) < 0)
		perror("Error calling getsockopt");
	else
		printf("Got socket option intent: %d\n", value);

}
