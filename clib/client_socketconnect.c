/** \file client_socketconnect.c
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt,
 *  Mirko Palmer, and Tobias Kaiser.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "dlog.h"

#include "intents.h"

#include "client_util.h"
#include "client_socketapi.h"
#include "client_socketconnect.h"
#include "muacc_ctx.h"

#ifndef CLIB_IF_NOISY_DEBUG0
#define CLIB_IF_NOISY_DEBUG0 1
#endif

#ifndef CLIB_IF_NOISY_DEBUG1
#define CLIB_IF_NOISY_DEBUG1 1
#endif

#ifndef CLIB_IF_NOISY_DEBUG2
#define CLIB_IF_NOISY_DEBUG2 1
#endif



struct socketset *socketsetlist = NULL;
pthread_rwlock_t socketsetlist_lock = PTHREAD_RWLOCK_INITIALIZER;


int muacc_sc_socketconnect(int *s, const char *host, size_t hostlen, const char *serv, size_t servlen, struct socketopt *sockopts, int domain, int type, int proto)
{
	struct socketset *candidate_set;
	int ret;
	muacc_context_t ctx;

	if (s == NULL)
		return -1;

	DLOG(CLIB_IF_NOISY_DEBUG0, "Socketconnect invoked, socket: %d\n", *s);

	muacc_init_context(&ctx);
	if (ctx.ctx == NULL)
	{
		return -1;
	}
	DLOG(CLIB_IF_NOISY_DEBUG2, "Context created\n");
	ctx.ctx->domain = domain;
	ctx.ctx->type = type;
	ctx.ctx->protocol = proto;
	ctx.ctx->sockopts_current = _muacc_clone_socketopts((const struct socketopt*) sockopts);
	if (_muacc_host_serv_to_ctx(&ctx, host, hostlen, serv, servlen) != 0)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "No hostname and service given this time!\n");
	}

	/* Search for corresponding socket set, unless we were explicitly told not to do so by *s. */
	if (*s != -1)
	{
		pthread_rwlock_wrlock(&socketsetlist_lock);
		DLOG(CLIB_IF_LOCKS, "LOCK: Looking up socket - Got global lock\n");

		if (*s == 0) /* No valid socket file descriptor passed - search by hostname, service, type */
			candidate_set = _muacc_find_set_for_socket(socketsetlist, ctx.ctx);
		else /* Search by socket file descriptor */
			candidate_set = _muacc_find_socketset(socketsetlist, *s);
	
		if (candidate_set != NULL)
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Found Socket Set\n");
			DLOG(CLIB_IF_LOCKS, "LOCK: Set found - Locking set %p\n", candidate_set);
			pthread_rwlock_rdlock(&(candidate_set->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Set found - Locking destroylock of set %p\n", candidate_set);
			pthread_rwlock_rdlock(&(candidate_set->destroylock));
		}
	
		DLOG(CLIB_IF_LOCKS, "LOCK: Unlocking global lock\n");
		pthread_rwlock_unlock(&socketsetlist_lock);
	}
	else
	{
		candidate_set = NULL;
	}
	
	if (candidate_set == NULL)
	{	
		/* Candidate set could be NULL either because *s == 1 or because the search for a reusable socket was unsuccessful.
		 * The request we send to the server is a socketconnect request. */
		DLOG(CLIB_IF_NOISY_DEBUG1, "No reusable socket candidate. Creating new socket.\n");
		if ((ret = _socketconnect_request(&ctx, s, host, hostlen, serv, servlen)) == -1)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Error creating a new socket!\n");
			muacc_release_context(&ctx);
			return -1;
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "New socket was successfully created!\n");
			muacc_release_context(&ctx);
			return 1;
		}
	}
	else
	{
		/* We found some sockets that we could possibly reuse, but we have to as MAM about that.
		 * The request we send to the server is a socketchoose request.
		 * The server will either choose one of the sockets we sent him, or create a new one, if the old ones are all found unsuitable. */
		DLOG(CLIB_IF_NOISY_DEBUG1, "Socket set found.\n");
		
		if (_muacc_host_serv_to_ctx(&ctx, host, hostlen, serv, servlen) != 0)
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "No hostname and service given this time - taking the one from the set: %s\n", candidate_set->sockets->ctx->remote_hostname);
			ctx.ctx->remote_hostname = _muacc_clone_string(candidate_set->sockets->ctx->remote_hostname);
			ctx.ctx->remote_service = _muacc_clone_string(candidate_set->sockets->ctx->remote_service);
		}

		if ((ret = _socketchoose_request (&ctx, s, candidate_set)) == -1)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socketchoose error!\n");
			muacc_release_context(&ctx);
			return -1;
		}
		else if (ret == 1)
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Successfully opened new socket.\n");
			muacc_release_context(&ctx);
			return 1;
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Successfully chose existing socket.\n");
			muacc_release_context(&ctx);
			return 0;
		}	
	}
}

int _socketconnect_request(muacc_context_t *ctx, int *s, const char *host, size_t hostlen, const char *serv, size_t servlen)
{
	if (ctx == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "No context given - aborting.\n");
		return -1;
	}
	else if (_muacc_host_serv_to_ctx(ctx, host, hostlen, serv, servlen) != 0)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Host or service not given - aborting.\n");
		return -1;
	}
	else
	{
		if (-1 == _muacc_contact_mam(muacc_act_socketconnect_req, ctx))
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Got no response from MAM (Is it running?) - Failing.\n");
			return -1;
		}

		return _muacc_socketconnect_create(ctx, s, &socketsetlist, &socketsetlist_lock, 0);
	}
}

int _socketchoose_request(muacc_context_t *ctx, int *s, struct socketset *set)
{
	int ret = -1;
	ret = _muacc_send_socketchoose (ctx, s, set);

	DLOG(CLIB_IF_LOCKS, "LOCK: Finished socketchoose - unlocking destroylock of set %p\n", set);
	pthread_rwlock_unlock(&(set->destroylock));

	if (ret == 0)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Chose existing socket %d\n", *s);
		return 0;
	}
	else if (ret == 1)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Open new socket:\n");
		if (CLIB_IF_NOISY_DEBUG2)
			muacc_print_context(ctx);

		return _muacc_socketconnect_create(ctx, s, &socketsetlist, &socketsetlist_lock, 0);
	}
	return -1;
}

int muacc_sc_socketclose(int socket)
{
	DLOG(CLIB_IF_NOISY_DEBUG0, "Trying to close socket %d and remove it from list\n", socket);
	pthread_rwlock_wrlock(&socketsetlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Closing socket - Got global lock\n");
	if (_muacc_remove_socket_from_list(&socketsetlist, socket) == -1)
	{
		DLOG(CLIB_IF_LOCKS, "LOCK: Finished trying to clean up set - Unlocking global lock\n");
		pthread_rwlock_unlock(&socketsetlist_lock);

		DLOG(CLIB_IF_NOISY_DEBUG1, "Could not remove socket %d from socketset list\n", socket);

		return -1;
	}
	else
	{
		DLOG(CLIB_IF_LOCKS, "LOCK: Finished trying to clean up set - Unlocking global lock\n");
		pthread_rwlock_unlock(&socketsetlist_lock);

		return 0;
	}
}

int muacc_sc_socketrelease(int socket)
{
	DLOG(CLIB_IF_NOISY_DEBUG0, "Releasing socket %d and marking it as free for reuse\n", socket);
	pthread_rwlock_wrlock(&socketsetlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Releasing socket - Got global lock\n");
	struct socketset *set_to_release = _muacc_find_socketset(socketsetlist, socket);
	if (set_to_release == NULL || set_to_release->sockets == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot mark as free\n", socket);
		DLOG(CLIB_IF_LOCKS, "LOCK: Socket not found - Unlocking global lock\n");
		pthread_rwlock_unlock(&socketsetlist_lock);
		return -1;
	}
	else
	{
		pthread_rwlock_wrlock(&(set_to_release->lock));
		DLOG(CLIB_IF_LOCKS, "LOCK: Releasing socket - Locking set %p\n", (void *)set_to_release);
		struct socketlist *slist = set_to_release->sockets;
		while (slist->file != socket && slist != NULL)
		{
			slist = slist->next;
		}
		if (slist == NULL)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot mark it as free\n", socket);
			pthread_rwlock_unlock(&(set_to_release->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Did not find socket - Releasing set %p\n", (void *) set_to_release);
			pthread_rwlock_unlock(&socketsetlist_lock);
			DLOG(CLIB_IF_LOCKS, "LOCK: Socket not found - Unlocking global lock\n");
			return -1;
		}
		else
		{
			slist->flags = slist->flags & ~MUACC_SOCKET_IN_USE;
			set_to_release->use_count -= 1;
			DLOG(CLIB_IF_NOISY_DEBUG2, "Socket set of %d: use count = %d\n", socket, set_to_release->use_count);

			pthread_rwlock_unlock(&(set_to_release->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Marked socket as free - Releasing set %p\n", (void *) set_to_release);

			DLOG(CLIB_IF_NOISY_DEBUG2, "Set entry of socket %d found and marked as free\n", socket);
		}
		pthread_rwlock_unlock(&socketsetlist_lock);
		DLOG(CLIB_IF_LOCKS, "LOCK: Finished releasing and cleaning up - Unlocking global lock\n");
		return 0;
	}
}

int muacc_sc_socketcleanup(int socket)
{
	DLOG(CLIB_IF_NOISY_DEBUG0, "Trying to close socket %d and clean up its socket set\n", socket);
	pthread_rwlock_wrlock(&socketsetlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Cleaning up socket list - Got global lock\n");

	struct socketset *set_to_cleanup = _muacc_find_socketset(socketsetlist, socket);
	if (set_to_cleanup == NULL || set_to_cleanup->sockets == NULL)
    {
        DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot clean up\n", socket);
        DLOG(CLIB_IF_LOCKS, "LOCK: Socket not found - Unlocking global lock\n");
        pthread_rwlock_unlock(&socketsetlist_lock);
        return -1;
    }
	else
	{
		pthread_rwlock_wrlock(&(set_to_cleanup->destroylock));
		DLOG(CLIB_IF_LOCKS, "LOCK: Cleaning up socket set - setting destroylock on %p\n", (void *)set_to_cleanup);
		pthread_rwlock_wrlock(&(set_to_cleanup->lock));
		DLOG(CLIB_IF_LOCKS, "LOCK: Cleaning up socket set - Locking set %p\n", (void *)set_to_cleanup);

		struct socketlist *slist = set_to_cleanup->sockets;
		while (slist->file != socket && slist != NULL)
		{
			slist = slist->next;
		}
		if (slist == NULL)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot mark it as free\n", socket);
			// Will still clean up though...
		}
		else
		{
			// Marking socket as free, so cleanup function will include it
			slist->flags = slist->flags & ~MUACC_SOCKET_IN_USE;
			set_to_cleanup->use_count -= 1;
			DLOG(CLIB_IF_NOISY_DEBUG2, "Socket set of %d: use count = %d\n", socket, set_to_cleanup->use_count);
		}

		DLOG(CLIB_IF_NOISY_DEBUG2, "Cleaning up socket set of socket %d\n", socket);
		if (1 == _muacc_cleanup_sockets(&set_to_cleanup))
		{
			// Set is empty now
			DLOG(CLIB_IF_NOISY_DEBUG2, "Socket set of %d was cleared completely - freeing it.\n", socket);
			struct socketset *prevset = _muacc_find_prev_socketset(&socketsetlist, set_to_cleanup);
			if (prevset != NULL)
			{
				prevset->next = set_to_cleanup->next;
				DLOG(CLIB_IF_NOISY_DEBUG2, "Readjusted socketset list pointers\n");
			}
			else
			{
				DLOG(CLIB_IF_NOISY_DEBUG2, "Freed the first list entry, reset head\n");
				socketsetlist = set_to_cleanup->next;
			}
			pthread_rwlock_destroy(&(set_to_cleanup->lock));
            DLOG(CLIB_IF_LOCKS, "LOCK: Removed socket set - destroyed its lock %p\n", (void *)set_to_cleanup);
            pthread_rwlock_destroy(&(set_to_cleanup->destroylock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Removed a socket from set - Releasing its destroylock %p\n", (void *)set_to_cleanup);
			free(set_to_cleanup);
		}
		else
		{
			// There are sockets left in the set
			DLOG(CLIB_IF_NOISY_DEBUG2, "Cleaned up some sockets in set, but is not empty\n");
			pthread_rwlock_unlock(&(set_to_cleanup->lock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Cleaned up - Releasing lock on set %p\n", (void *) set_to_cleanup);
			pthread_rwlock_unlock(&(set_to_cleanup->destroylock));
			DLOG(CLIB_IF_LOCKS, "LOCK: Cleaned up - Releasing destroylock of set %p\n", (void *) set_to_cleanup);
		}
	}
	DLOG(CLIB_IF_NOISY_DEBUG2, "Socket set of socket %d cleaned up\n", socket);
	pthread_rwlock_unlock(&socketsetlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Finished releasing and cleaning up - Unlocking global lock\n");
	return 0;
}