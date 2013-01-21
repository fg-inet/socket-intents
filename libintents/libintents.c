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
#include "libintents.h"

/* Original functions */
int (*orig_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int (*orig_getsockopt)(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

int setintent(int sockfd, int optname, const void *optval, socklen_t optlen);
int getintent(int sockfd, int optname, void *optval, socklen_t *optlen);

/* Overloading functions */
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
	/* 
	 * Intercepts all 'setsockopt' calls.
	 * If the socket option is an intent, handle it. 
	 * Else, pass it on to the original setsockopt function.
	 */
{
	LOG("You have called the experimental setsockopt function on level %d option %d value %d \n", level, optname, *(int *) optval);

	int opterror = 0;
	if (level == SOL_INTENTS)
	{
		/*
		 * Setsockopt was called on SOL_INTENTS level
		 * so we handle it ourselves
		 */
		LOG("Trying to set socket intent option.\n");
		if ((opterror = setintent(sockfd, optname, optval, optlen)) < 0)
		{
			LOG("Error calling setintent.\n");
		}
		else
		{
			LOG("Successfully set %d option: %d.\n", optname, *(int *) optval);
		}
	}
	else
		/*
		 * Setsockopt was called on another level than SOL_INTENTS
		 * so we call the original setsockopt function
		 */
	{
		LOG("Trying to call the original setsockopt function.\n");
		char *error = NULL;
		error = dlerror();
		orig_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
		if ((error = dlerror()) != NULL)
		{
			printf("Could not find original setsockopt function: %s\n", error);
			return -1;
		}

		if ((opterror = orig_setsockopt(sockfd, level, optname, optval, optlen)) < 0)
		{
			LOG("Error calling original setsockopt.\n");
		}
		else
		{
			LOG("Successfully set %d option to %d. \n", optname, *(int *) optval);
		}
	}
	return opterror;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
	/*
	 * Intercept all 'getsockopt' calls.
	 * If the socket option is an intent, handle it.
	 * Else, pass it on to the original getsockopt function.
	 */
{
	LOG("You have called the experimental getsockopt function on level %d option %d value %d \n", level, optname, *(int *) optval);

	int opterror = 0;
	if (level == SOL_INTENTS) 
	{
		/*
		 * Getsockopt was called on SOL_INTENTS level
		 * so we handle it ourselves
		 */
		LOG("Trying to get socket intent option.\n");
		if ((opterror = getintent(sockfd, optname, optval, optlen)) < 0)
		{
			LOG("Error calling getintent.\n");
		}
		else
		{
			LOG("Successfully gotten %d option: %d.\n", optname, *(int *) optval);
		}
	}
	else
		/*
		 * Getsockopt was called on another level than SOL_INTENTS
		 * so we call the original getsockopt function
		 */
	{
		LOG("Trying to call the original getsockopt function.\n");
		char *error = NULL;
		error = dlerror();
		orig_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
		if ((error = dlerror()) != NULL)
		{
			printf("Could not find original getsockopt function: %s\n", error);
			return -1;
		}


		if ((opterror = orig_getsockopt(sockfd, level, optname, optval, optlen)) < 0)
		{
			LOG("Error calling original getsockopt.\n");
		}
		else
		{
			LOG("Successfully gotten %d option: %d. \n", optname, *(int *)optval);
		}
	}
	return opterror;
}

int getintent(int sockfd, int optname, void *optval, socklen_t *optlen)
{
	/* Not yet implemented. */
	errno = ENOSYS;
	return -1;
}

int setintent(int sockfd, int optname, const void *optval, socklen_t optlen)
{
	/* Not yet implemented. */
	errno = ENOSYS;
	return -1;
}
