/*
 * Socket library, extending the Socket API to support intents
 * 
 * Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>
 *
 */

#define DEBUG

#ifdef DEBUG
 #define LOG printf
 #else
 #define LOG if(0) printf
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "libintents.h"
#include "../clib/muacc.h"

/* Original functions */
int (*orig_socket)(int domain, int type, int protocol) = NULL;
int (*orig_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen) = NULL;
int (*orig_getsockopt)(int sockfd, int level, int optname, void *optval, socklen_t *optlen) = NULL;
//int (*orig_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, const addrinfo **res);

int setintent(int sockfd, int optname, const void *optval, socklen_t optlen);
int getintent(int sockfd, int optname, void *optval, socklen_t *optlen);

int get_orig_function(char* name, void** function);

/* Overloading functions */

int socket(int domain, int type, int protocol)
{
	LOG("You have called the experimental socket function.\n");
	static bool call_in_progress = false;
	int retval = 0;

	if (!orig_socket)
	{
		if ((retval = get_orig_function("socket", (void **)&orig_socket)) != 0)
		{
			call_in_progress = false;
			return retval;
		}
	}

	if (call_in_progress)
	{
		LOG("Call in progress - calling original socket function\n");
		return orig_socket(domain, type, protocol);
	}
	else
	{
		LOG("Set 'call in progress' to true\n");
		call_in_progress = true;
	}

	LOG("Initializing muacc context.\n");
	muacc_context_t testctx = {.ctx = NULL};
	if (muacc_init_context(&testctx) < 0)
	{
		fprintf(stderr,"Error initializing context\n");
		errno = ENOMEM;
	}
	else
	{
		LOG("Initialized new muacc_context.\n");
	}

	LOG("Creating socket.\n");
	if ((retval = orig_socket(domain, type, protocol)) < 0)
	{
		fprintf(stderr, "Error creating socket.\n");
	}
	else
	{
		LOG("Successfully created socket %d \n", retval);
	}
	call_in_progress = false;
	return retval;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
	/* 
	 * Intercepts all 'setsockopt' calls.
	 * If the socket option is an intent, handle it. 
	 * Else, pass it on to the original setsockopt function.
	 */
{
	LOG("You have called the experimental setsockopt function on level %d option %d value %d \n", level, optname, *(int *) optval);
	int retval = 0;

	if (level == SOL_INTENTS)
	{
		/*
		 * Setsockopt was called on SOL_INTENTS level
		 * so we handle it ourselves
		 */
		LOG("Trying to set socket intent option.\n");
		if ((retval = setintent(sockfd, optname, optval, optlen)) < 0)
		{
			fprintf(stderr,"Error calling setintent.\n");
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

		if (!orig_setsockopt)
		{
			if ((retval = get_orig_function("setsockopt",(void **)&orig_setsockopt)) != 0)
			{
				return retval;
			}
		}

		if ((retval = orig_setsockopt(sockfd, level, optname, optval, optlen)) < 0)
		{
			fprintf(stderr,"Error calling original setsockopt.\n");
		}
		else
		{
			LOG("Successfully set %d option to %d. \n", optname, *(int *) optval);
		}
	}
	return retval;
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
			fprintf(stderr,"Error calling getintent.\n");
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

		if (!orig_getsockopt)
		{
			if (get_orig_function("getsockopt",(void **)&orig_getsockopt) < 0) return -1;
		}

		if ((opterror = orig_getsockopt(sockfd, level, optname, optval, optlen)) < 0)
		{
			fprintf(stderr,"Error calling original getsockopt.\n");
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

int get_orig_function(char* name, void** function)
{
	if (name == NULL)
	{
		fprintf(stderr,"Could not get original function of NULL.\n");
		return -1;
	}
	LOG("Trying to get the original %s function\n", name);

	char *error = NULL;
	error = dlerror();
	*function = dlsym(RTLD_NEXT, name);
	if ((error = dlerror()) != NULL)
	{
		fprintf(stderr,"Could not find original %s function: %s\n", name, error);
		return -1;
	}
	else
	{
		LOG("Found original %s function.\n", name);
	}
	return 0;
}
