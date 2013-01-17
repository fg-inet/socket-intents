/*
 * Socket library, extending the Socket API to support intents
 * 
 * Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>
 *
 */

#define _GNU_SOURCE
#define DEBUG

#ifdef DEBUG
 #define LOG printf
 #else
 #define LOG if(0) printf
#endif

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* Original functions */
int (*orig_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

/* Overloading functions */
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
	/* 
	 * Intercepts all 'setsockopt' calls.
	 * If the socket option is an intent, handle it. 
	 * Else, pass it on to the original setsockopt function.
	 */
{
	char *error = NULL;
	int opterror = 0;

	LOG("You have called the experimental setsockopt function.\n");

	error = dlerror();
	orig_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
	if ((error = dlerror()) != NULL)
		printf("Error calling dlsym %s\n", error);

	LOG("Trying to call setsockopt %x\n",orig_setsockopt);

	if ((opterror = orig_setsockopt(sockfd, level, optname, optval, optlen)) < 0)
	{
		int errsv = errno;
		printf("Setsockopt returned %d: ", opterror);
		if (errsv == ENOPROTOOPT)
			printf("Option is unknown. \n");
		if (errsv == EINVAL)
			printf("Got EINVAL\n");
	}

	return opterror;
}


