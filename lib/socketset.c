/** \file socketset.c
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
*/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

#include "dlog.h"
#include "muacc_ctx.h"
#include "muacc_tlv.h"
#include "muacc_util.h"
#include "intents.h"
#include "muacc.h"

#include "socketset.h"

// TODO: Change names of the noisy debug switches

#ifndef MUACC_CLIENT_UTIL_NOISY_DEBUG0
#define MUACC_CLIENT_UTIL_NOISY_DEBUG0 1
#endif

#ifndef MUACC_CLIENT_UTIL_NOISY_DEBUG1
#define MUACC_CLIENT_UTIL_NOISY_DEBUG1 1
#endif

#ifndef MUACC_CLIENT_UTIL_NOISY_DEBUG2
#define MUACC_CLIENT_UTIL_NOISY_DEBUG2 1
#endif


struct socketlist *_muacc_socketlist_find_file (struct socketlist *slist, int socket)
{
       while (slist != NULL)
       {
               if (slist->file == socket)
                       return slist;
               slist = slist->next;
       }
       return NULL;
}


struct socketset* _muacc_add_socket_to_set(struct socketset **list_of_sets, int socket, struct _muacc_ctx *ctx)
{
	struct socketset *set = NULL;
	struct socketset *newset = NULL;

	if ((set = _muacc_find_set_for_socket(*list_of_sets, ctx)) == NULL)
	{
		/* No matching socket set - create it */
		newset = malloc(sizeof(struct socketset));
		if (newset == NULL)
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Could not allocate memory for socketset for socket %d!\n", socket);
			return NULL;
		}
		newset->next = NULL;

		if (0 != pthread_rwlock_init(&(newset->lock), NULL) || 0 != pthread_rwlock_init(&(newset->destroylock), NULL))
		{
			// Setting up the locks failed
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Could not initiate the locks for socketset for socket %d!\n", socket);
			return NULL;
		}

		newset->host = _muacc_clone_string(ctx->remote_hostname);
		newset->hostlen = (newset->host == NULL ? 0 : strlen(newset->host));
		newset->serv = _muacc_clone_string(ctx->remote_service);
		newset->servlen = (newset->serv == NULL ? 0 : strlen(newset->serv));
		newset->type = ctx->type;

		newset->sockets = malloc(sizeof(struct socketlist));
		if (newset->sockets == NULL)
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Could not allocate memory for socketlist of socket %d!\n", socket);
			return NULL;
		}
		newset->sockets->next = NULL;
		newset->sockets->file = socket;
		newset->sockets->flags = 0;
		newset->sockets->flags |= MUACC_SOCKET_IN_USE;
		newset->use_count = 1;
		newset->sockets->ctx = _muacc_clone_ctx(ctx);

		if (*list_of_sets == NULL)
		{
			*list_of_sets = newset;
		}
		else
		{
			while ((*list_of_sets)->next !=NULL)
			{
				list_of_sets = &((*list_of_sets)->next);
			}
			(*list_of_sets)->next = newset;
		}
		return newset;
	}
	else
	{
		pthread_rwlock_wrlock(&(set->lock));
		DLOG(CLIB_IF_LOCKS, "LOCK: Adding new socket to set - Locking %p\n", (void *) set);

		struct socketlist *slist = set->sockets;

		/* Add socket to existing socket set */
		while (slist->next != NULL)
		{
			if (slist->file == socket)
			{
				// This socket already exists in the set!
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d already exists in the set -- aborting!\n", socket);
				DLOG(CLIB_IF_LOCKS, "LOCK: Finished trying to add - Releasing set %p\n", (void *) set);
				pthread_rwlock_unlock(&(set->lock));
				return set;
			}
			slist = slist->next;
		}
		slist->next = malloc(sizeof(struct socketset));
		if (slist->next == NULL)
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Could not allocate memory for set of socket %d!\n", socket);
			return NULL;
		}
		slist->next->next = NULL;
		slist->next->file = socket;
		slist->next->flags = 0;
		slist->next->flags |= MUACC_SOCKET_IN_USE;
		set->use_count += 1;
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Added %d - Use count of socket set is now %d\n", socket, set->use_count);
		slist->next->ctx = _muacc_clone_ctx(ctx);

		DLOG(CLIB_IF_LOCKS, "LOCK: Finished trying to add - Releasing set %p\n", (void *) set);
		pthread_rwlock_unlock(&(set->lock));
		return set;
	}
	return NULL;
}


struct socketset *_muacc_find_set_for_socket(struct socketset *list_of_sets, struct _muacc_ctx *ctx)
{
	if (ctx->remote_hostname == NULL || ctx->remote_service == NULL)
			return NULL;

	while (list_of_sets != NULL)
	{
		if (list_of_sets->type == ctx->type && (strncmp(list_of_sets->host, ctx->remote_hostname, list_of_sets->hostlen+1) == 0) && (strncmp(list_of_sets->serv, ctx->remote_service, list_of_sets->servlen+1) == 0))
		{
			// Found a socket set that matches the given context!
			// Note that we compare the "service" string, and only group sockets with the same "service"
			// So sockets with "443" and "https" will end up in different sets, despite having the same port
			return list_of_sets;
		}

		list_of_sets = list_of_sets->next;
	}

	return NULL;
}

struct socketset *_muacc_find_socketset(struct socketset *list_of_sets, int socket)
{
	while (list_of_sets != NULL )
	{
		struct socketlist *list = _muacc_socketlist_find_file (list_of_sets->sockets, socket);

		if (list != NULL)
			// Found a socket set that contains a socket with the given file descriptor!
			return list_of_sets;

		list_of_sets = list_of_sets->next;
	}
	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socketlist for %d not found\n", socket);
	return NULL;
}


struct socketlist *_muacc_socketset_find_dup (struct socketlist *slist)
{
	struct socketlist *duplicate = slist->next;

	while (duplicate != NULL)
	{
		if (duplicate->ctx == slist->ctx)
		{
			// Found duplicate! (i.e. different file descriptor, but same socket context)
			break;
		}
		duplicate = duplicate->next;
	}

	return duplicate;
}

struct socketset *_muacc_find_prev_socketset(struct socketset **list_of_sets, struct socketset *set)
{
	if (*list_of_sets == NULL || set == NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Previous set of NULL is NULL\n");
		return NULL;
	}

	if (*list_of_sets == set)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "This is the first set in the list\n");
		return NULL;
	}

	struct socketset *prevset = *list_of_sets;

	while (prevset->next != NULL)
	{
		if (prevset->next == set)
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Prevset found!\n");
			return prevset;
		}
		prevset = prevset->next;
	}

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Set not found in list - returning NULL\n");
	return NULL;
}

int _muacc_remove_socket_from_list (struct socketset **list_of_sets, int socket)
{
	struct socketlist *currentlist = NULL;
	struct socketset *currentset = *list_of_sets;

	struct socketlist *list_to_delete = NULL;
	struct socketlist *prevlist = NULL;
	struct socketset *set_to_delete = NULL;
	struct socketset *prevset = NULL;

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Trying to delete socket %d from set\n", socket);

	while (currentset != NULL)
	{

		// Go through list of sockets
		currentlist = currentset->sockets;

		if (currentlist->file == socket)
		{
			// First socket matches!

			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: First socket matches!\n", socket);
			pthread_rwlock_wrlock(&(currentset->destroylock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Planning to delete set - locked destroylock %p\n", (void *) currentset);
			pthread_rwlock_wrlock(&(currentset->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Planning to delete set - locked %p\n", (void *) currentset);
			set_to_delete = currentset; // Found the set to delete!
			list_to_delete = currentlist; // Store list entry of set
			prevlist = NULL;
			break;
		}

		while (currentlist->next != NULL)
		{

			// Set has more than one socket, iterate through it
			if (currentlist->next->file == socket)
			{
				// Socket matches!

				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: Found socket to delete\n", socket);
				pthread_rwlock_wrlock(&(currentset->destroylock));
				DLOG(CLIB_IF_LOCKS, "LOCK: Planning to delete set - locked destroylock %p\n", (void *) currentset);
				pthread_rwlock_wrlock(&(currentset->lock));
				DLOG(CLIB_IF_LOCKS, "LOCK: Planning to delete set - locked %p\n", (void *) currentset);
				list_to_delete = currentlist->next; // Found the socket to delete!
				set_to_delete = currentset; // Store set
				prevlist = currentlist;
			}

			currentlist = currentlist->next;
		}

		if (list_to_delete != NULL)
		{
			// Found socket to delete!
			break;
		}

		prevset = currentset;

		currentset = currentset->next;
	}

	if (set_to_delete == NULL || list_to_delete == NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d not found in set!\n", socket);
		return -1;
	}
	else
	{
		// Decrease set use count
		set_to_delete->use_count -= 1;
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: Decreased use count to %d\n", socket, set_to_delete->use_count);
		int ret;
		if ((ret = _muacc_free_socket(set_to_delete, list_to_delete, prevlist)) == 0 && set_to_delete->use_count == 0)
		{
			// Returnvalue is still 0, so there are still sockets in the set
			pthread_rwlock_unlock(&(set_to_delete->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Removed a socket from set - Releasing its lock %p\n", (void *)set_to_delete);
			pthread_rwlock_unlock(&(set_to_delete->destroylock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Removed a socket from set - Releasing its destroylock %p\n", (void *)set_to_delete);
		}
		else if (ret == 1)
		{
			// Last socket was freed, so set can be freed
			if (prevset != NULL)
			{
				// This is not the first socket set in the list
				prevset->next = set_to_delete->next;
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: Freeing a socket set, readjusted socketset list pointers\n", socket);
			}
			else
			{
				// This IS the first socket set in the list
				*list_of_sets = set_to_delete->next;
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: Freeing the first socketset list entry, reset head\n", socket);
			}

			pthread_rwlock_destroy(&(set_to_delete->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Removed socket set - destroyed its lock %p\n", (void *)set_to_delete);
			pthread_rwlock_destroy(&(set_to_delete->destroylock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Removed a socket from set - Releasing its destroylock %p\n", (void *)set_to_delete);

			free(set_to_delete);
		}
		else
		{
			// Error
			pthread_rwlock_unlock(&(set_to_delete->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Error trying to remove socket - Releasing set lock %p\n", (void *)set_to_delete);
			pthread_rwlock_unlock(&(set_to_delete->destroylock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Error trying to remove socket - Releasing set destroylock %p\n", (void *)set_to_delete);
		}

		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Set for socket %d successfully cleared\n", socket);
	}

	return 0;
}


int _muacc_cleanup_sockets(struct socketset **set)
{
	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Freeing unused sockets from set\n");
	struct socketlist *sockets = (*set)->sockets;
	struct socketlist *socket_to_delete = NULL;
	struct socketlist *prevsocket = NULL;
	int returnvalue = -1;

	while (sockets != NULL)
	{
		if (!(sockets->flags & MUACC_SOCKET_IN_USE))
		{
			// Socket is not in use
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket %d not in use -- freeing\n", sockets->file);
			socket_to_delete = sockets;
			sockets = sockets->next;

			if ((returnvalue = _muacc_free_socket(*set, socket_to_delete, prevsocket)) == 1)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "This was the last socket in the set.\n");
			}
		}
		else
		{
			prevsocket = sockets;
			sockets = sockets->next;
		}
	}

	return returnvalue;
}


int _muacc_free_socket(struct socketset *set_to_delete, struct socketlist *list_to_delete, struct socketlist *prevlist)
{
	int returnvalue = -1;
	int socketfd = list_to_delete->file;

	// Free context if no other file descriptor needs it
	if (_muacc_socketset_find_dup(list_to_delete) == NULL)
	{
		// No duplicate (i.e., no other file descriptor shares this socket/context)
		_muacc_free_ctx(list_to_delete->ctx);
	}

	// Re-adjust pointers
	if (prevlist != NULL)
	{
		// This is not the first socket of the set
		prevlist->next = list_to_delete->next;
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: Readjusted set pointers\n", list_to_delete->file);
		returnvalue = 0;
	}
	else
	{
		// This IS the first socket of the set
		if (list_to_delete->next != NULL)
		{
			// There are more sockets in the set
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: This is the first socket in the set - readjusting pointer\n", list_to_delete->file);
			set_to_delete->sockets = list_to_delete->next;
			returnvalue = 0;
		}
		else
		{
			// This was the only socket in the set - clear this set
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: This is the ONLY socket in the set - need to free set\n", list_to_delete->file);
			returnvalue = 1;
		}
		free(list_to_delete);
	}

	// Close the socket
	if (close(socketfd) == -1)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "DEL %d: Close failed\n", socketfd);
		returnvalue = -1;
	}
	else
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: Closed socket.\n", socketfd);
	}


	return returnvalue;
}

void muacc_print_socketsetlist(struct socketset *list_of_sets)
{
	printf("\n\t\tList of Socketsets:\n{ ");
	while (list_of_sets != NULL)
	{
		muacc_print_socketset(list_of_sets);
		printf("} <next socket set...>\n");

		list_of_sets = list_of_sets->next;
	}
	printf("}\n\n");
}

void muacc_print_socketset(struct socketset *set)
{
	printf("{ ");
	printf("host = %s\n", (set->host == NULL ? "(null)" : set->host));
	printf("serv = %s\n", (set->serv == NULL ? "(null)" : set->serv));
	printf("type = %d\n", set->type);
	printf("use_count = %d\n", set->use_count);
	struct socketlist *list = set->sockets;
	while (list != NULL)
	{
		strbuf_t sb;
		strbuf_init(&sb);

		printf("{ file = %d\n", list->file);
		printf("flags = %d\n", list->flags);
		printf("ctx = ");
		_muacc_print_ctx(&sb, list->ctx);
		printf("%s", strbuf_export(&sb));
		strbuf_release(&sb);

		list = list->next;
		printf("} ");
	}
}
