/** \file libintents.c
 *  \brief 	Socket library, extending the Socket API to support intents -
 *  		Does NOT provide any guarantees or quality of service of any kind.
 * 
 *  Socket library that is intended to overload some socket API calls to support intents.
 *  Communicates socket intents to a Multi Access Manager (MAM) which translates the intents
 *  into concrete effects on the sockets.
 */

/** Print a very verbose output of what the overloaded functions are doing by using -DDEBUG
 *  Otherwise, print nothing and optimize code out.
 */
#ifdef DEBUG
 #define LOG printf
 #else
 #define LOG if(0) printf
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <glib.h>
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
int (*orig_close)(int fd) = NULL;

/** \var int (*orig_socket)(int domain, int type, int protocol)
 *  Pointer to the 'original' socket function in the library that would be loaded without LD_PRELOAD
 */
/** \var int (*orig_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
 *  Pointer to the 'original' setsockopt function in the library that would be loaded without LD_PRELOAD
 */
/** \var int (*orig_getsockopt)(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
 *  Pointer to the 'original' getsockopt function in the library that would be loaded without LD_PRELOAD
 */
/** \var int (*orig_close)(int fd)
 *  Pointer to the 'original' close function in the library that would be loaded without LD_PRELOAD
 */


GHashTable *socket_table = NULL;
static void st_free_socknum(void* data);
static void st_free_ctx(void* data);
static void st_print_table(GHashTable* table);

int setintent(int sockfd, int optname, const void *optval, socklen_t optlen);
int getintent(int sockfd, int optname, void *optval, socklen_t *optlen);

int get_orig_function(char* name, void** function);

/* Overloading functions */

/** Intercepts all 'socket' calls.
 *
 *  Creates a new socket and initializes a new \a muacc_context_t for it.
 */
int socket(int domain, int type, int protocol)
{
	LOG("You have called the experimental socket function.\n");

	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;

	if (!orig_socket)
	{
		/* If the original socket function has not been called yet, we need to find it
		 * for being able to call it later.
		 */
		if ((retval = get_orig_function("socket", (void **)&orig_socket)) != 0)
		{
			call_in_progress = false;
			return retval;
		}
	}
	/* Check if we are in a nested call of our experimental socket function.
	 * If so, call the original socket function and return afterwards to prevent loops.
	 */
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

	if (!socket_table)
	{
		LOG("Initializing socket table\n");
		socket_table = g_hash_table_new_full(g_int_hash, g_int_equal, st_free_socknum, st_free_ctx);
	}

	LOG("Creating socket.\n");
	if ((retval = orig_socket(domain, type, protocol)) < 0)
	{
		fprintf(stderr, "Error creating socket.\n");
	}
	else
	{
		LOG("Successfully created socket %d \n", retval);

		LOG("Initializing muacc context.\n");
		muacc_context_t *newctx = malloc(sizeof(muacc_context_t));
		newctx -> ctx = NULL;
		if (muacc_init_context(newctx) < 0)
		{
			fprintf(stderr,"Error initializing context\n");
			errno = ENOMEM;
		}
		else
		{
			LOG("Initialized new muacc_context.\n");
		}
		//FIXME Move hash table insert inside the 'else'
		LOG("Inserting socket %d and its muacc_context into hash table.\n",retval);
		int *socknum = malloc(sizeof(int));
		*socknum = retval;
		g_hash_table_insert(socket_table, (void *) socknum, (void *) newctx);

	}

	call_in_progress = false;
	return retval;
}

/** Intercepts all 'setsockopt' calls.
 *
 * If the socket option is an intent, handle it.
 * Else, pass it on to the original setsockopt function.
 */
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	LOG("You have called the experimental setsockopt function on level %d option %d value %d \n", level, optname, *(int *) optval);
	int retval = 0;

	if (level == SOL_INTENTS)
	{
		/* Setsockopt was called on SOL_INTENTS level
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
		/* Setsockopt was called on another level than SOL_INTENTS
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

/** Intercept all 'getsockopt' calls.
 *
 * If the socket option is an intent, handle it.
 * Else, pass it on to the original getsockopt function.
 */
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	LOG("You have called the experimental getsockopt function on level %d option %d value %d \n", level, optname, *(int *) optval);

	int opterror = 0;
	if (level == SOL_INTENTS) 
	{
		/* Getsockopt was called on SOL_INTENTS level
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
		/* Getsockopt was called on another level than SOL_INTENTS
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

int close(int fd)
{
	LOG("You have called the experimental close function.\n");
	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;
	if (!orig_close)
	{
		if ((retval = get_orig_function("close",(void **)&orig_close)) < 0) return retval;
	}
	if (call_in_progress)
	{
		LOG("Call already in progress. Calling original connect.\n");
		return orig_close(fd);
	}
	else
	{
		LOG("Set call_in_progress to true.\n");
		call_in_progress = true;
	}

	LOG("Trying to remove socket %d from socket table.\n", fd);
	if (!(retval = g_hash_table_remove(socket_table, (const void*) &fd)))
	{
		fprintf(stderr, "Could not find socket %d in socket table - nothing removed.\n", fd);
	}
	else
	{
		LOG("Successfully removed socket %d from socket table.\n", fd);
	}

	LOG("Calling original close.\n");
	if ((retval = orig_close(fd)) < 0)
	{
		fprintf(stderr,"Error calling original close.\n");
	}
	
	call_in_progress = false;
	return retval;
}


/** Get an intent from the multi access context.
 */
int getintent(int sockfd, int optname, void *optval, socklen_t *optlen)
{
	muacc_context_t *setctx = g_hash_table_lookup(socket_table, (const void *) &sockfd);

	if (setctx == NULL)
	{
		fprintf(stderr, "Failed to look up socket %d in socket table - Aborting.\n", sockfd);
		errno = EOPNOTSUPP;
		return -1;
	}
	else
	{
		LOG("Found context matching socket %d\n", sockfd);
	}

	//TODO: Get the intent from the context.

	return 0;
}

/** Set an intent to the multi access context.
 */
int setintent(int sockfd, int optname, const void *optval, socklen_t optlen)
{
	muacc_context_t *setctx = g_hash_table_lookup(socket_table, (const void *) &sockfd);
	/*muacc_context_t *setctx = NULL;
	printf("hash blah %d to %d\n", sockfd, g_int_hash((const void*) &sockfd));
	g_hash_table_lookup(socket_table, (const void *) &sockfd);*/

	if (setctx == NULL)
	{
		fprintf(stderr, "Failed to look up socket %d in socket table - Aborting.\n", sockfd);
		errno = EOPNOTSUPP;
		return -1;
	}
	else
	{
		LOG("Found context matching socket %d\n", sockfd);
	}

	//TODO: Insert the intent into the context.

	return 0;
}

/** Fetch the 'original' function from the library that would be used without LD_PRELOAD.
 *  \param name The name of the function/symbol
 *  \param function Buffer where a pointer to the function will be placed on success
 *  \return 0 on success, -1 otherwise
 */
int get_orig_function(char* name, void** function)
{
	if (name == NULL)
	{
		fprintf(stderr,"Could not get original function of NULL.\n");
		return -1;
	}
	LOG("Trying to get the original %s function\n", name);

	/* Clear error string before fetching a pointer to \a name from the library that would
	 * come next in the LD Library Path. Place the pointer in \a **function.
	 */
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

void st_print_table(GHashTable* table)
{
	if (table == NULL)
	{
		fprintf(stderr, "Cannot print NULL table.\n");
	}
	else
	{
		GList *keys = g_hash_table_get_keys(table);
		if (keys == NULL)
		{
			printf("Table has no keys.\n");
		}
		else
		{
			int *blah = keys->data;
			printf("Socket %d, muacc_context %d\n", *blah, (int) g_hash_table_lookup(table, (const void *) keys->data));
			for (GList *current = keys; current->next == current; current = current->next)
			{
				int *blub = current->next->data;
				printf("Socket %d, muacc_context %d\n", *blub, (int) g_hash_table_lookup(table, (const void *) current->next->data));
			}
		}

		g_list_free(keys);
	}
}

void st_free_socknum(void* data)
{
	int *sock = data;
	if ( sock == NULL )
	{
		fprintf(stderr, "Cannot free NULL.\n");
	}
	else
	{
		free(sock);
	}
}

void st_free_ctx(void* data)
{
	struct muacc_context *ctx = data;
	if ( ctx == NULL)
	{
		fprintf(stderr,"Cannot free NULL muacc_context.\n");
	}
	else if ( ctx->ctx == NULL)
	{
		LOG("Freeing empty muacc_context.\n");
		free(ctx);
		return;
	}
	else
	{
		muacc_release_context(data);
	}
}
