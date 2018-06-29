/** \file client_socketconnect_async.c
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt,
 *  Mirko Palmer, and Tobias Kaiser.
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
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <assert.h>

#include "lib/dlog.h"
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"
#include "lib/intents.h"

#include "client_util.h"
#include "muacc_util.h"
#include "config.h"

#ifndef CLIB_IF_NOISY_DEBUG0
#define CLIB_IF_NOISY_DEBUG0 1
#endif

#ifndef CLIB_IF_NOISY_DEBUG1
#define CLIB_IF_NOISY_DEBUG1 1
#endif

#ifndef CLIB_IF_NOISY_DEBUG2
#define CLIB_IF_NOISY_DEBUG2 1
#endif


/*****************************************************************************
 * Struct declaration                                                        *
 *****************************************************************************/
/* Global list of all file descriptors, which were previously asynchronously
 * opened by socketconnect_a and still need attention. */
struct postponed_muacc_context {
	int fd;
	muacc_context_t ctx;
	enum {
		SOCKETCONNECT_SENT,
		SOCKETCHOOSE_SENT
	} state;
	struct socketset *candidate_set;
	struct postponed_muacc_context *next;
};



/*****************************************************************************
 * Global variables                                                          *
 *****************************************************************************/

static struct socketset *async_socketsetlist = NULL;
static pthread_mutex_t async_io_global_lock = PTHREAD_MUTEX_INITIALIZER;
static struct postponed_muacc_context *postponed_ctx_list=NULL;


/*****************************************************************************
 * Forward declarations of everything that follows in this file              *
 *****************************************************************************/

/* External asynchronous (and thread-safe) API */
int muacc_sca_socketconnect(int *s, const char *host, size_t hostlen, const char *serv, size_t servlen, struct socketopt *sockopts, int domain, int type, int proto);
int muacc_sca_socketclose(int socket);
int muacc_sca_socketrelease(int socket);
int muacc_sca_socketcleanup(int socket);
int muacc_sca_socketselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

/* All asynchronous action functions regarding the socketconnect request */
int _socketconnect_request_a(muacc_context_t *ctx, int *s, const char *host, size_t hostlen, const char *serv, size_t servlen);
int _muacc_contact_mam_a (muacc_mam_action_t reason, muacc_context_t *ctx);
int _socketconnect_request_a_response(struct postponed_muacc_context *ppc);

/* All asynchronous action functions regarding the socketchoose request */
int _socketchoose_request_a(muacc_context_t *ctx, int *s, struct socketset *set);
int _muacc_send_socketchoose_a (muacc_context_t *ctx, int *socket, struct socketset *set);
int _socketchoose_request_a_response(struct postponed_muacc_context *ppc);

/* process_response: Calls appropriate response function, replaces dummy fd */
static int process_response(struct postponed_muacc_context *ppc);

static int rename_fd_in_socketsets(int new_fd, int old_fd);

/* Helper functions for the postponed_ctx_list */
static void postpone_context(struct postponed_muacc_context *insert, int state);
static void remove_postponed_context(struct postponed_muacc_context *remove);

/* Helper functions to handle struct timevals */
static struct timeval *tv_add(struct timeval *dst, struct timeval *src);
static struct timeval *tv_sub(struct timeval *dst, struct timeval *src);


/*****************************************************************************
 * External API: socket{connect, close, release, cleanup, select}_a          *
 *****************************************************************************/

int muacc_sca_socketconnect(int *s, const char *host, size_t hostlen, const char *serv, size_t servlen, struct socketopt *sockopts, int domain, int type, int proto)
{
	
	struct postponed_muacc_context *ppc;
	struct socketset *candidate_set;
	int ret;

	if (s == NULL)
		return -1;

	pthread_mutex_lock(&async_io_global_lock);
	DLOG(CLIB_IF_NOISY_DEBUG0, "Socketconnect_a invoked, socket: %d\n", *s);

	ppc = malloc(sizeof(struct postponed_muacc_context));
	if (ppc == NULL)
	{
		pthread_mutex_unlock(&async_io_global_lock);
		return -1;
	}

	memset(ppc, 0, sizeof(struct postponed_muacc_context));

	muacc_init_context(&ppc->ctx);

	if (ppc->ctx.ctx == NULL)
	{
		pthread_mutex_unlock(&async_io_global_lock);
		return -1;
	}
	DLOG(CLIB_IF_NOISY_DEBUG2, "Context created\n");
	ppc->ctx.ctx->domain = domain;
	ppc->ctx.ctx->type = type;
	ppc->ctx.ctx->protocol = proto;
	ppc->ctx.ctx->sockopts_current = _muacc_clone_socketopts((const struct socketopt*) sockopts);
	if (_muacc_host_serv_to_ctx(&ppc->ctx, host, hostlen, serv, servlen) != 0)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "No hostname and service given this time!\n");
	}

	/* Search for corresponding socket set, unless we were explicitly told not to do so by *s. */
	if (*s != -1)
	{

		if (*s == 0) /* No valid socket file descriptor passed - search by hostname, service, type */
			candidate_set = _muacc_find_set_for_socket(async_socketsetlist, ppc->ctx.ctx);
		else /* Search by socket file descriptor */
			candidate_set = _muacc_find_socketset(async_socketsetlist, *s);
	
	}
	else
	{
		candidate_set = NULL;
	}
	
	if (candidate_set != NULL && candidate_set->socketchoose_pending)
	{
		/* Even though we have found a set of sockets which we could reuse, we won't attempt to send them to MAM, 
		 * as MAM is still processing a previous socketchoose request. Instead, we will fall back to socketconnect. */
		 candidate_set = NULL;
	}


	if (candidate_set == NULL)
	{
		/* Candidate set could be NULL either because *s == 1 or because the search for a reusable socket was unsuccessful.
		 * The request we send to the server is a socketconnect request. */
		DLOG(CLIB_IF_NOISY_DEBUG1, "No reusable socket candidate. Creating new socket.\n");

		if ((ret = _socketconnect_request_a(&ppc->ctx, s, host, hostlen, serv, servlen)) == -1)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Error creating a new socket!\n");
			muacc_release_context(&ppc->ctx);
			free(ppc);
			pthread_mutex_unlock(&async_io_global_lock);
			return -1;
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "New dummy socket was created, context postponed.\n");
			ppc->fd=*s;
			postpone_context(ppc, SOCKETCONNECT_SENT);
			pthread_mutex_unlock(&async_io_global_lock);
			return 1;
		}
	}
	else
	{
		/* We found some sockets that we could possibly reuse, but we have to as MAM about that.
		 * The request we send to the server is a socketchoose request.
		 * The server will either choose one of the sockets we sent him, or create a new one, if the old ones are all found unsuitable. */
		DLOG(CLIB_IF_NOISY_DEBUG1, "Socket set found.\n");
			
		if (_muacc_host_serv_to_ctx(&ppc->ctx, host, hostlen, serv, servlen) != 0)
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "No hostname and service given this time - taking the one from the set: %s\n", candidate_set->sockets->ctx->remote_hostname);
			ppc->ctx.ctx->remote_hostname = _muacc_clone_string(candidate_set->sockets->ctx->remote_hostname);
			ppc->ctx.ctx->remote_service = _muacc_clone_string(candidate_set->sockets->ctx->remote_service);
		}

		if ((ret = _socketchoose_request_a (&ppc->ctx, s, candidate_set)) == -1)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socketchoose error!\n");
			muacc_release_context(&ppc->ctx);
			free(ppc);
			pthread_mutex_unlock(&async_io_global_lock);
			return -1;
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "New dummy socket was created, context postponed.\n");
			ppc->fd=*s;
			ppc->candidate_set = candidate_set;
			candidate_set->socketchoose_pending=1;
			postpone_context(ppc, SOCKETCHOOSE_SENT);
			pthread_mutex_unlock(&async_io_global_lock);
			return 2;
		}
	}	
}

int muacc_sca_socketclose(int socket)
{
	pthread_mutex_lock(&async_io_global_lock);
	DLOG(CLIB_IF_NOISY_DEBUG0, "Trying to close socket %d and remove it from list\n", socket);
	
	if (_muacc_remove_socket_from_list(&async_socketsetlist, socket) == -1)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Could not remove socket %d from socketset list\n", socket);
		pthread_mutex_unlock(&async_io_global_lock);
		return -1;
	}
	else
	{
		pthread_mutex_unlock(&async_io_global_lock);
		return 0;
	}
}

int muacc_sca_socketrelease(int socket)
{
	pthread_mutex_lock(&async_io_global_lock);
	DLOG(CLIB_IF_NOISY_DEBUG0, "Releasing socket %d and marking it as free for reuse\n", socket);
	
	struct socketset *set_to_release = _muacc_find_socketset(async_socketsetlist, socket);
	if (set_to_release == NULL || set_to_release->sockets == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot mark as free\n", socket);
		pthread_mutex_unlock(&async_io_global_lock);
		return -1;
	}
	else
	{
		struct socketlist *slist = set_to_release->sockets;
		while (slist->file != socket && slist != NULL)
		{
			slist = slist->next;
		}
		if (slist == NULL)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot mark it as free\n", socket);
			pthread_mutex_unlock(&async_io_global_lock);
			return -1;
		}
		else
		{
			slist->flags = slist->flags & ~MUACC_SOCKET_IN_USE;
			set_to_release->use_count -= 1;
			DLOG(CLIB_IF_NOISY_DEBUG2, "Socket set of %d: use count = %d\n", socket, set_to_release->use_count);

			DLOG(CLIB_IF_NOISY_DEBUG2, "Set entry of socket %d found and marked as free\n", socket);
		}
		pthread_mutex_unlock(&async_io_global_lock);
		return 0;
	}
}

int muacc_sca_socketcleanup(int socket)
{
	pthread_mutex_lock(&async_io_global_lock);
	DLOG(CLIB_IF_NOISY_DEBUG0, "Trying to close socket %d and clean up its socket set\n", socket);
	
	struct socketset *set_to_cleanup = _muacc_find_socketset(async_socketsetlist, socket);
	if (set_to_cleanup == NULL || set_to_cleanup->sockets == NULL)
    {
        DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot clean up\n", socket);
        pthread_mutex_unlock(&async_io_global_lock);
        return -1;
    }
	else
	{
		
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
			struct socketset *prevset = _muacc_find_prev_socketset(&async_socketsetlist, set_to_cleanup);
			if (prevset != NULL)
			{
				prevset->next = set_to_cleanup->next;
				DLOG(CLIB_IF_NOISY_DEBUG2, "Readjusted socketset list pointers\n");
			}
			else
			{
				DLOG(CLIB_IF_NOISY_DEBUG2, "Freed the first list entry, reset head\n");
				async_socketsetlist = set_to_cleanup->next;
			}
			
			free(set_to_cleanup);
		}
		else
		{
			// There are sockets left in the set
			DLOG(CLIB_IF_NOISY_DEBUG2, "Cleaned up some sockets in set, but is not empty\n");
		}
	}
	DLOG(CLIB_IF_NOISY_DEBUG2, "Socket set of socket %d cleaned up\n", socket);
	pthread_mutex_unlock(&async_io_global_lock);
	return 0;
}

int muacc_sca_socketselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	pthread_mutex_lock(&async_io_global_lock);
	if(nfds != FD_SETSIZE)
	{
		errno=EINVAL;
		return -1;
	}
	
	bool mam_response_processed;
	int retval;
	
	fd_set readfds_copy, writefds_copy, exceptfds_copy;
	
	struct timeval end;
	if(timeout)
	{
		gettimeofday(&end, NULL);
		tv_add(&end, timeout);
	}
	
	do
	{
		struct postponed_muacc_context *ppc;
		
		memcpy(&readfds_copy, readfds, sizeof(fd_set));
		memcpy(&writefds_copy, writefds, sizeof(fd_set));
		memcpy(&exceptfds_copy, exceptfds, sizeof(fd_set));
		
		for(ppc=postponed_ctx_list;ppc;ppc=ppc->next)
		{
			/* If we want to do either r, w or x with any postponed context,
			 * get the dummy fd out of the set (fix for https://lkml.org/lkml/2001/3/31/29)
			 * and wait for MAM's response.
			 */
			if(FD_ISSET(ppc->fd, &readfds_copy))
			{
				FD_CLR(ppc->fd, &readfds_copy);
				FD_SET(ppc->ctx.mamsock, &readfds_copy);
			}
			
			if(FD_ISSET(ppc->fd, &writefds_copy))
			{
				FD_CLR(ppc->fd, &writefds_copy);
				FD_SET(ppc->ctx.mamsock, &readfds_copy);
			}
			
			if(FD_ISSET(ppc->fd, &exceptfds_copy))
			{
				FD_CLR(ppc->fd, &exceptfds_copy);
				FD_SET(ppc->ctx.mamsock, &readfds_copy);
			}
		}
			
		struct timeval now, timeout_left;
		if(timeout)
		{
			gettimeofday(&now, NULL);
			timeout_left=end;
			tv_sub(&timeout_left, &now);
			if(timeout_left.tv_sec<0)
			{
				timeout_left.tv_sec=0;
				timeout_left.tv_usec=0;
			}
		}
		
		retval=select(FD_SETSIZE, &readfds_copy, &writefds_copy, &exceptfds_copy,timeout?&timeout_left:NULL);
		
		mam_response_processed=false;
		struct postponed_muacc_context *next;
		for(ppc=postponed_ctx_list;ppc;ppc=next)
		{
			next=ppc->next; /* we need to save this reference here in case process_response removed the ppc from the list. */
		
			if(FD_ISSET(ppc->ctx.mamsock, &readfds_copy))
			{
				// If _any_ mamsock is readable, we have to call process the queued response from MAM with process_mam
				// and we cannot return the current xxxfds
				if(0 > process_response(ppc))
				{
					DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING : process_response failed\n");
					goto error;
				}
				mam_response_processed=true;
			}
		}	
	
	}
	while(mam_response_processed);
	
	memcpy(readfds, &readfds_copy, sizeof(fd_set));
	memcpy(writefds, &writefds_copy, sizeof(fd_set));
	memcpy(exceptfds, &exceptfds_copy, sizeof(fd_set));
	
	pthread_mutex_unlock(&async_io_global_lock);
	
	return retval;
	
error:
	// TODO: this is probably a big problem: what to do here
	errno=EINVAL;
	pthread_mutex_unlock(&async_io_global_lock);
	return -1;
}


/*****************************************************************************
 * All asynchronous action functions regarding the socketconnect request     *
 *****************************************************************************/


int _socketconnect_request_a(muacc_context_t *ctx, int *s, const char *host, size_t hostlen, const char *serv, size_t servlen)
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
		if (-1 == _muacc_contact_mam_a(muacc_act_socketconnect_req, ctx))
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Got no response from MAM (Is it running?) - Failing.\n");
			return -1;
		}

		// Create temporary socket that we will later dup2 away
		*s=socket(AF_INET, SOCK_STREAM, 0);
		
		if(*s==-1) {
			DLOG(CLIB_IF_NOISY_DEBUG1, "socket call failed.\n");
			return -1;
		}
		
		return 0;
	}
}

int _muacc_contact_mam_a (muacc_mam_action_t reason, muacc_context_t *ctx)
{
	char buf[MUACC_TLV_MAXLEN];
	ssize_t pos = 0;
	ssize_t ret = 0;
	
	/* connect to MAM */
	if(	_muacc_connect_ctx_to_mam(ctx) != 0 )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: failed to contact MAM\n");
	}

	DLOG(CLIB_IF_NOISY_DEBUG2, "Serializing MAM context\n");

	/* pack request */
	if( 0 > _muacc_push_tlv(buf, &pos, sizeof(buf), action, &reason, sizeof(muacc_mam_action_t)) ) goto  _muacc_contact_mam_pack_err;
	if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), ctx->ctx) ) goto  _muacc_contact_mam_pack_err;
	if( 0 > _muacc_push_tlv_tag(buf, &pos, sizeof(buf), eof) ) goto  _muacc_contact_mam_pack_err;
	DLOG(CLIB_IF_NOISY_DEBUG2,"Serializing MAM context done - Sending it to MAM\n");

	/* send request */
	if( 0 > (ret = send(ctx->mamsock, buf, pos, 0)) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: error sending request: %s\n", strerror(errno));
		goto _muacc_contact_mam_connect_err;
	}
	else
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Request sent  - %ld of %ld bytes\n", (long int) ret, (long int) pos);
	}

	return 0;
_muacc_contact_mam_connect_err:
	return(-1);

_muacc_contact_mam_pack_err:

	DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: failed to serialize MAM context\n");
	return(-1);
}

/* 0 on success but continue, 1 on success and finish, -1 on failure. */
int _socketconnect_request_a_response(struct postponed_muacc_context *ppc)
{

	muacc_context_t *ctx=&ppc->ctx;

	char buf[MUACC_TLV_MAXLEN];
	ssize_t pos = 0;


	/* read & unpack response */
	int ret;
	muacc_tlv_t tag;
	void *data;
	ssize_t data_len;
	
	DLOG(CLIB_IF_NOISY_DEBUG0, "Processing response \n");
	pos = 0;
	while( (ret = _muacc_read_tlv(ctx->mamsock, buf, &pos, sizeof(buf), &tag, &data, &data_len)) > 0)
	{
		if( tag == eof )
			break;
		else if ( 0 > _muacc_unpack_ctx(tag, data, data_len, ctx->ctx) )
			return -1;
	}
	
	int new_fd;
	
	if(0 > _muacc_socketconnect_create(ctx, &new_fd, &async_socketsetlist, NULL, 1))
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: _muacc_socketconnect_create failed\n");
		return -1;
	}
	
	rename_fd_in_socketsets(ppc->fd, new_fd);
	dup2(new_fd, ppc->fd); // This call really takes source first and destination second
	close(new_fd);
	
	
	return 1; // success and finished
}


/*****************************************************************************
 * All asynchronous action functions regarding the socketchoose request      *
 *****************************************************************************/

int _socketchoose_request_a(muacc_context_t *ctx, int *s, struct socketset *set)
{
	return _muacc_send_socketchoose_a (ctx, s, set);

}

int _muacc_send_socketchoose_a (muacc_context_t *ctx, int *socket, struct socketset *set)
{


	DLOG(CLIB_IF_NOISY_DEBUG0, "Sending socketchoose\n");

	char buf[MUACC_TLV_MAXLEN];
	ssize_t pos = 0;
	ssize_t ret = 0;
	
	muacc_mam_action_t reason = muacc_act_socketchoose_req;

	struct socketlist *list = set->sockets;

	if ( _muacc_connect_ctx_to_mam(ctx) != 0 )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: failed to contact MAM\n");
		return -1;
	}

	DLOG(CLIB_IF_NOISY_DEBUG2, "Serializing MAM context\n");
	if ( 0 > _muacc_push_tlv(buf, &pos, sizeof(buf), action, &reason, sizeof(muacc_mam_action_t)) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Error pushing label\n");
		return -1;
	}

	/* Pack context from request */
	if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Error serializing socket context \n");
		return -1;
	}

	/* Pack sockets from socketset */
	while (list != NULL)
	{
		// Suggest all sockets that are currently not in use to MAM
		if ((list->flags & MUACC_SOCKET_IN_USE) == 0)
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Pushing socket %d\n", list->file);
			if ( 0 > _muacc_push_tlv(buf, &pos, sizeof(buf), socketset_file, &(list->file), sizeof(int)) )
			{
				DLOG(CLIB_IF_NOISY_DEBUG1, "Error pushing socket with file descriptor %d\n", list->file);
				return -1;
			}
			if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), list->ctx) )
			{
				DLOG(CLIB_IF_NOISY_DEBUG1, "Error pushing socket context of %d\n", list->file);
				return -1;
			}
		}
		list = list->next;
	}
	if( 0 > _muacc_push_tlv_tag(buf, &pos, sizeof(buf), eof) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Error pushing eof\n");
		return -1;
	}
	DLOG(CLIB_IF_NOISY_DEBUG2, "Pushing request done\n");

	if ( 0 > (ret = send(ctx->mamsock, buf, pos, 0)) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Error sending request: %s\n", strerror(errno));
		return -1;
	}
	
	DLOG(CLIB_IF_NOISY_DEBUG2, "Sent request - %ld of %ld bytes\n", (long int) ret, (long int) pos);
	return 0;
}

int _socketchoose_request_a_response(struct postponed_muacc_context *ppc)
{
	assert(ppc->candidate_set->socketchoose_pending);
	ppc->candidate_set->socketchoose_pending=0;
	
	muacc_context_t *ctx = &ppc->ctx;
	
	struct socketset *set = ppc->candidate_set;

	char buf[MUACC_TLV_MAXLEN];
	ssize_t pos = 0;
	

	/* read & unpack response */
	int ret;
	muacc_tlv_t tag;
	void *data;
	ssize_t data_len;

	/* read & unpack response */
    DLOG(CLIB_IF_NOISY_DEBUG0, "Getting response:\n");
    pos = 0;
	
	int reuse_fd = -1;
	bool reuse_socket = false;

    while( (ret = _muacc_read_tlv(ctx->mamsock, buf, &pos, sizeof(buf), &tag, &data, &data_len)) > 0)
    {
		if (tag == action)
		{
			if (*(muacc_mam_action_t *) data == muacc_act_socketchoose_resp_existing)
			{
				DLOG(CLIB_IF_NOISY_DEBUG0, "MAM says: Use existing socket!\n");

				reuse_socket = true;
			}
			else if (*(muacc_mam_action_t *) data == muacc_act_socketchoose_resp_new)
			{
				DLOG(CLIB_IF_NOISY_DEBUG0, "MAM says: Open a new socket!\n");
				//reuse_fd=-1; would be logical here, but could have unintended side effects.
			}
			else if (*(muacc_mam_action_t *) data == muacc_error_unknown_request)
			{
				DLOG(CLIB_IF_NOISY_DEBUG1, "Error: MAM sent error code \"Unknown Request\" -- Aborting.\n");
				return -1;
			}
			else
			{
				DLOG(CLIB_IF_NOISY_DEBUG1, "Error: Unknown MAM Response Action Type\n");
				return -1;
			}
		}
		else if (tag == socketset_file && data_len == sizeof(int))
		{
			if (reuse_socket)
			{
				reuse_fd=*(int *) data;
				
				return 0;
			}
			else
			{
				DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d suggested, but there was no muacc_act_socketchoose_resp_existing -- fail\n", *(int *)data);
				return -1;
			}
		}
        else if( tag == eof )
            break;
        else
		{
			if ( 0 > _muacc_unpack_ctx(tag, data, data_len, ctx->ctx) )
			{
				DLOG(CLIB_IF_NOISY_DEBUG1, "Error unpacking context\n");

				return -1;
			}
		}
    }
    DLOG(CLIB_IF_NOISY_DEBUG0, "Socketchoose done, reuse_fd = %d, reuse_socket = %d\n", reuse_fd, reuse_socket);
	
	if(reuse_socket && reuse_fd > 0)
	{
		/* Find item with fd in socket set */
		struct socketlist *item;
		item = set->sockets;
		while (item != NULL && item->file != reuse_fd)
		{
			item = item->next;
		}

		if (item == NULL)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d suggested, but not found in set -- this should not have happened.\n", *(int *)data);
			return -1;
		}
		
		if ((item->flags & MUACC_SOCKET_IN_USE))
		{
			// Socket is already in use, so we cannot use it
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d suggested, but is already in use -- this should not have happened.\n", *(int *) data);
			return -1;
		}
		
		// Socket is not in use yet - set flag as IN USE
		item->flags |= MUACC_SOCKET_IN_USE;
		
		set->use_count += 1;
		

		// Rename the chosen socket to the previously issued dummy socket

		rename_fd_in_socketsets(ppc->fd, reuse_fd);
		dup2(reuse_fd, ppc->fd); // This call really takes source first and destination second
		close(reuse_fd);
		

		DLOG(CLIB_IF_NOISY_DEBUG2, "Use socket %d (previously %d) - use count of set is now %d\n", ppc->fd, reuse_fd, set->use_count);

		return 1; // success and finish
	}
	else
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Open new socket:\n");
		int new_fd;
	
		if(0 > _muacc_socketconnect_create(ctx, &new_fd, &async_socketsetlist, NULL, 1))
		{
			DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: _muacc_socketconnect_create failed\n");
			return -1;
		}
		
		rename_fd_in_socketsets(ppc->fd, new_fd);
		dup2(new_fd, ppc->fd); // This call really takes source first and destination second
		close(new_fd);
		
		return 1; // success and finish
	}
	
	//dup2(new_fd, ppc->fd); // This call really takes source first and destination second
	//close(new_fd);
}
 
/*****************************************************************************
 * process_response: Calls appropriate response function, replaces dummy fd  *
 *****************************************************************************/

static int process_response(struct postponed_muacc_context *ppc)
{ 
	int ret;
	switch(ppc->state)
	{
		case SOCKETCONNECT_SENT:
			DLOG(CLIB_IF_NOISY_DEBUG0, "Calling handler to process socketconnect response.\n");
			ret = _socketconnect_request_a_response(ppc);
			break;
			
		case SOCKETCHOOSE_SENT:
			DLOG(CLIB_IF_NOISY_DEBUG0, "Calling handler to process socketchoose response.\n");
			ret = _socketchoose_request_a_response(ppc);
			
			break;
			
		default:
			ret=-1;
			DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: Postponed context in unknown state.\n");
			break;
	}
	
	if (ret == 0) // success, but keep postponed
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "Successfully processed postponed context, but it remains postponed.\n");
	
		return 0;
	} 
	else if (ret == 1) // success and finished
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "Successfully finished processing postponed context.\n");
	
		muacc_release_context(&ppc->ctx);
		remove_postponed_context(ppc);
		free(ppc);
		
		return 0;
	}
	else // failure, finish somehow.
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: Failed to process postponed context.\n");
	
		muacc_release_context(&ppc->ctx);
		remove_postponed_context(ppc);
		free(ppc);
	
		return -1;
	}
}

static int rename_fd_in_socketsets(int new_fd, int old_fd)
{
	struct socketset *set=_muacc_find_socketset(async_socketsetlist, old_fd);
	if(!set)
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: Failed to rename fd %d to %d: socket set for fd not found\n", old_fd, new_fd);
		return -1;
	}
		
	struct socketlist *item;
	item = set->sockets;
	while (item != NULL && item->file != old_fd)
	{
		item = item->next;
	}

	if (item == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: Failed to rename fd %d to %d: fd not found in socket set\n", old_fd, new_fd);
		return -1;
	}
	
	assert(item->file==old_fd);
	item->file=new_fd;
	assert(item->ctx->sockfd==old_fd);
	item->ctx->sockfd=new_fd;
	DLOG(CLIB_IF_NOISY_DEBUG0, "Renamed fd %d to %d\n", old_fd, new_fd);
	return 0;
}

/*****************************************************************************
 * Helper functions for the postponed_ctx_list                               *
 *****************************************************************************/

static void postpone_context(struct postponed_muacc_context *insert, int state)
{
	insert->state=state;

	insert->next=postponed_ctx_list;
	postponed_ctx_list=insert;
}

static void remove_postponed_context(struct postponed_muacc_context *remove)
{
	struct postponed_muacc_context **ptr;
	for(ptr=&postponed_ctx_list;*ptr;ptr=&((*ptr)->next))\
	{
		if(*ptr==remove)
		{
			*ptr = remove->next;
			return;
		}
	}
}

/*****************************************************************************
 * Helper functions to handle struct timevals                                *
 *****************************************************************************/ 

#define ONE_MILLION 1000000

static struct timeval *tv_add(struct timeval *dst, struct timeval *src)
{
	assert(dst->tv_usec < ONE_MILLION && dst->tv_usec >= 0);	
	assert(src->tv_usec < ONE_MILLION && src->tv_usec >= 0);
	
	dst->tv_usec+=src->tv_usec;
	if(dst->tv_usec >= ONE_MILLION)
	{
		dst->tv_usec-=ONE_MILLION;
		dst->tv_sec+=1;
	}
	dst->tv_sec+=src->tv_sec;
	
	return dst;
}

static struct timeval *tv_sub(struct timeval *dst, struct timeval *src)
{
	assert(dst->tv_usec < ONE_MILLION && dst->tv_usec >= 0);
	assert(src->tv_usec < ONE_MILLION && src->tv_usec >= 0);
	
	dst->tv_usec-=src->tv_usec;
	if(dst->tv_usec < 0)
	{
		dst->tv_usec+=ONE_MILLION;
		dst->tv_sec-=1;
	}
	dst->tv_sec-=src->tv_sec;
	
	return dst;
}
