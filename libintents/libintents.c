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
int (*orig_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;
int (*orig_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
int (*orig_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
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
/** \var int (*orig_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
 *  Pointer to the 'original' getaddrinfo function in the library that would be loaded without LD_PRELOAD
 */
/** \var int (*orig_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
 *  Pointer to the 'original' bind function in the library that would be loaded without LD_PRELOAD
 */
/** \var int (*orig_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
 *  Pointer to the 'original' connect function in the library that would be loaded without LD_PRELOAD
 */
/** \var int (*orig_close)(int fd)
 *  Pointer to the 'original' close function in the library that would be loaded without LD_PRELOAD
 */


GHashTable *socket_table = NULL;
static void st_free_socknum(void* data);
static void st_free_ctx(void* data);
static void st_print_table(GHashTable* table);

int get_orig_function(char* name, void** function);

/* Overloading functions */

/** Intercepts all 'socket' calls.
 *
 *  Creates a new socket and initializes a new \a muacc_context_t for it.
 */
int socket(int domain, int type, int protocol)
{
	LOG("--- socket( %d, %d, %d ) ---\n", domain, type, protocol);

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
		LOG("+++ Initializing socket table +++\n");
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

		LOG("+++ Initializing muacc context. +++\n");
		muacc_context_t *newctx = malloc(sizeof(muacc_context_t));
		newctx -> ctx = NULL;
		if (muacc_init_context(newctx) < 0)
		{
			fprintf(stderr,"Error initializing context for socket %d. \n", retval);
			errno = ENOMEM;
		}
		else
		{
			LOG("Initialized new muacc_context: %d\n", (int) newctx);
		}
		//FIXME Move hash table insert inside the 'else'
		LOG("+++ Inserting socket %d and its muacc_context into hash table. +++\n",retval);
		int *socknum = malloc(sizeof(int));
		*socknum = retval;
		g_hash_table_insert(socket_table, (void *) socknum, (void *) newctx);
		#ifdef DEBUG
		st_print_table(socket_table);
		#endif

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
	LOG("--- setsockopt ( %d, %d, %d, %d, %d ) --- \n", sockfd, level, optname, *(int *) optval, (int) optlen);
	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;

	if (!orig_setsockopt)
	{
		if ((retval = get_orig_function("setsockopt",(void **)&orig_setsockopt)) != 0) return retval;
	}
	if (call_in_progress)
	{
		LOG("Call already in progress. Calling original setsockopt.\n");
		return orig_setsockopt(sockfd, level, optname, optval, optlen);
	}
	else
	{
		LOG("setsockopt: Set call_in_progress to true.\n");
		call_in_progress = true;
	}

	muacc_context_t *ctx = g_hash_table_lookup(socket_table, (const void *) &sockfd);
	if (ctx == NULL)
	{
		fprintf(stderr, "Failed to look up socket %d in socket table - calling original setsockopt.\n", sockfd);
		call_in_progress = false;
		return orig_setsockopt(sockfd, level, optname, optval, optlen);
	}
	else
	{
		LOG("Found context matching socket %d - calling muacc_setsockopt.\n", sockfd);
		if ((retval = muacc_setsockopt(ctx, sockfd, level, optname, optval, optlen)) < 0)
		{
			fprintf(stderr, "Error calling muacc_setsockopt: %d\n", retval);
		}
	}
	call_in_progress = false;
	return retval;
}

/** Intercept all 'getsockopt' calls.
 *
 * If the socket option is an intent, handle it.
 * Else, pass it on to the original getsockopt function.
 */
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	LOG("--- getsockopt ( %d, %d, %d, %d, %d ) --- \n", sockfd, level, optname, *(int *) optval, *(int*) optlen);
	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;

	if (!orig_getsockopt)
	{
		if ((retval = get_orig_function("getsockopt",(void **)&orig_getsockopt)) != 0) return retval;
	}
	if (call_in_progress)
	{
		LOG("Call already in progress. Calling original getsockopt.\n");
		return orig_getsockopt(sockfd, level, optname, optval, optlen);
	}
	else
	{
		LOG("getsockopt: Set call_in_progress to true.\n");
		call_in_progress = true;
	}

	muacc_context_t *ctx = g_hash_table_lookup(socket_table, (const void *) &sockfd);
	if (ctx == NULL)
	{
		fprintf(stderr, "Failed to look up socket %d in socket table - calling original getsockopt.\n", sockfd);
		call_in_progress = false;
		return orig_getsockopt(sockfd, level, optname, optval, optlen);
	}
	else
	{
		LOG("Found context matching socket %d - calling muacc_getsockopt.\n", sockfd);
		if ((retval = muacc_getsockopt(ctx, sockfd, level, optname, optval, optlen)) < 0)
		{
			fprintf(stderr, "Error calling muacc_getsockopt.\n");
		}
	}
	#ifdef DEBUG
	muacc_print_context(ctx);
	#endif
	call_in_progress = false;
	return retval;
}

/** Intercept all 'getaddrinfo' calls.
 *
 */
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
	LOG("--- getaddrinfo ( %s, %s ) ---\n", node, service);
	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;

	if (!orig_getaddrinfo)
	{
		if ((retval = get_orig_function("getaddrinfo",(void **)&orig_getaddrinfo)) < 0) return retval;
	}

	if (call_in_progress)
	{
		LOG("Call already in progress. Calling original getaddrinfo.\n");
		return orig_getaddrinfo(node, service, hints, res);
	}
	else
	{
		LOG("Set call_in_progress to true.\n");
		call_in_progress = true;
	}

	int sockfd = 1; //FIXME: How to get a socket descriptor that makes sense here?
	muacc_context_t *ctx = g_hash_table_lookup(socket_table, (const void *) &sockfd);

	if (ctx == NULL)
	{
		fprintf(stderr, "Failed to look up socket %d in socket table - calling original getaddrinfo.\n", sockfd);
		return orig_getaddrinfo(node, service, hints, res);
	}
	else
	{
		LOG("Found context matching socket %d\n", sockfd);
	}
	LOG("Calling muacc_getaddrinfo.\n");
	if ((retval = muacc_getaddrinfo(ctx, node, service, hints, res)) < 0)
	{
		fprintf(stderr,"Error calling muacc_getaddrinfo.\n");
	}

	call_in_progress = false;
	return retval;
}

/** Intercept all 'bind' calls.
 *
 */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	LOG("--- bind ( %d ) --- \n", sockfd);
	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;

	if (!orig_bind)
	{
		if ((retval = get_orig_function("bind",(void **)&orig_bind)) < 0) return retval;
	}

	if (call_in_progress)
	{
		LOG("Call already in progress. Calling original bind.\n");
		return orig_bind(sockfd, addr, addrlen);
	}
	else
	{
		LOG("Set call_in_progress to true.\n");
		call_in_progress = true;
	}

	LOG("Calling original bind.\n");
	if ((retval = orig_bind(sockfd, addr, addrlen)) < 0)
	{
		fprintf(stderr,"Error calling bind.\n");
	}
	call_in_progress = false;
	return retval;
}

/** Intercept all 'connect' calls.
 *
 */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	LOG("--- connect ( %d ) --- \n", sockfd);
	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;

	if (!orig_connect)
	{
		if ((retval = get_orig_function("connect",(void **)&orig_connect)) < 0) return retval;
	}
	if (call_in_progress)
	{
		LOG("Call already in progress. Calling original connect.\n");
		return orig_connect(sockfd, addr, addrlen);
	}
	else
	{
		LOG("Set call_in_progress to true.\n");
		call_in_progress = true;
	}

	muacc_context_t *ctx = g_hash_table_lookup(socket_table, (const void *) &sockfd);

	if (ctx == NULL)
	{
		fprintf(stderr, "Failed to look up socket %d in socket table - Just connecting.\n", sockfd);
		return orig_connect(sockfd, addr, addrlen);
	}
	else
	{
		LOG("Found context matching socket %d\n", sockfd);
	}

	LOG("Calling muacc_connect.\n");

	if ((retval = muacc_connect(ctx, sockfd, addr, addrlen)) < 0)
	{
		fprintf(stderr,"Error calling muacc_connect.\n");
	}
	call_in_progress = false;
	return retval;
}

int close(int fd)
{
	LOG("--- close ( %d ) ---\n", fd);
	static bool call_in_progress = false; // Flag that indicates if this is a nested call
	int retval = 0;
	if (!orig_close)
	{
		if ((retval = get_orig_function("close",(void **)&orig_close)) < 0) return retval;
	}
	if (call_in_progress)
	{
		LOG("Call already in progress. Calling original close.\n");
		return orig_close(fd);
	}
	else
	{
		LOG("Set call_in_progress to true.\n");
		call_in_progress = true;
	}

	if (socket_table != NULL)
	{
		LOG("+++ Trying to remove socket %d from socket table. +++\n", fd);
		if (!(retval = g_hash_table_remove(socket_table, (const void*) &fd)))
		{
			fprintf(stderr, "Could not find socket %d in socket table - nothing removed.\n", fd);
		}
		else
		{
			LOG("+++ Successfully removed socket %d from socket table. +++\n", fd);
		}
	}

	LOG("Calling original close.\n");
	if ((retval = orig_close(fd)) < 0)
	{
		fprintf(stderr,"Error calling original close.\n");
	}
	
	call_in_progress = false;
	return retval;
}

/** Fetch the 'original' function from the library that would be used without LD_PRELOAD.
 *  \param name The name of the function/symbol
 *  \param function Buffer where a pointer to the function will be placed on success
 *  \return 0 on success, -1 otherwise
 */
int get_orig_function(char* name, void** function)
{
	if (name == NULL || function == NULL)
	{
		fprintf(stderr,"Could not get original function of NULL.\n");
		return -1;
	}
//	LOG("Trying to get the original %s function\n", name);

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
//		LOG("Found original %s function.\n", name);
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
			printf("+++ Printing table +++\n");
			for (GList *current = keys; current != NULL; current = current->next)
			{
				int *item = current->data;
				printf("Socket %d, muacc_context %d\n", *item, (int) g_hash_table_lookup(table, (const void *) item));
			}
			printf("+++ End of table +++\n");
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
	int retval = 0;

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
		if ((retval = muacc_release_context(ctx)) > 0)
		{
			fprintf(stderr, "Could not free muacc context: Usage counter still at %d\n", retval);
		}
	}
}
