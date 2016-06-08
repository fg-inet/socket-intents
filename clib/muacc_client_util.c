/** \file muacc_client_util.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
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
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"
#include "lib/intents.h"

#include "muacc_client_util.h"
#include "config.h"

#ifndef MUACC_CLIENT_UTIL_NOISY_DEBUG0
#define MUACC_CLIENT_UTIL_NOISY_DEBUG0 0
#endif

#ifndef MUACC_CLIENT_UTIL_NOISY_DEBUG1
#define MUACC_CLIENT_UTIL_NOISY_DEBUG1 1
#endif

#ifndef MUACC_CLIENT_UTIL_NOISY_DEBUG2
#define MUACC_CLIENT_UTIL_NOISY_DEBUG2 0
#endif

int muacc_init_context(struct muacc_context *ctx)
{
	struct _muacc_ctx *_ctx = _muacc_create_ctx();

	if(_ctx == NULL || ctx == NULL)
		return(-1);

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0,"Context successfully initialized\n");

	ctx->usage = 1;
	ctx->locks = 0;
	ctx->mamsock = -1;

	ctx->ctx = _ctx;
	return(0);
}

muacc_ctxino_t _muacc_get_ctxino(int sockfd)
{
    struct stat s;
    fstat(sockfd, &s);
    return s.st_ino;
}

int _is_socket_open(int sockfd)
{
    char dummy;
    return recv(sockfd, &dummy, 1, MSG_PEEK);
}

int _lock_ctx (muacc_context_t *ctx)
{
    return( -(ctx->locks++) );
}

int _unlock_ctx (muacc_context_t *ctx)
{
    return( -(--(ctx->locks)) );
}

int muacc_retain_context(struct muacc_context *ctx)
{
	if(ctx->ctx == NULL)
	{
		return(-1);
	}

	return(++(ctx->usage));
}

void muacc_print_context(struct muacc_context *ctx)
{
	strbuf_t sb;

	if (ctx == NULL)
	{
		dprintf(muacc_debug_fd, "ctx = NULL\n");
	}
	else if (ctx->ctx == NULL)
	{
		dprintf(muacc_debug_fd, "ctx->ctx = NULL\n");
	}
	else
	{
		strbuf_init(&sb);
		_muacc_print_ctx(&sb, ctx->ctx);
		dprintf(muacc_debug_fd, "/**************************************/\n%s\n/**************************************/\n", strbuf_export(&sb));
		strbuf_release(&sb);
	}
}

int muacc_release_context(struct muacc_context *ctx)
{
	if(ctx == NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: tried to release NULL POINTER context\n");
		return -1;
	}
	else if(ctx->ctx == NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "empty context - nothing to release\n");
		return 0;
	}
	else
	{
		if( --(ctx->usage) == 0 )
		{
			if (ctx->mamsock != -1) 				close(ctx->mamsock);
			return _muacc_free_ctx(ctx->ctx);
		} else {
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "context has still %d references\n", ctx->usage);
			return(ctx->usage);
		}
	}
}


int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src)
{
	if (dst == NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0,"WARNING: cloning into empty context\n");
		return 0;
	}

	if (src == NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0,"WARNING: cloning uninitialized context\n");
		dst->ctx = NULL;
	}
	else
	{
		dst->ctx = _muacc_clone_ctx(src->ctx);
	}

/*<<<<<<< HEAD
	memcpy(_ctx, src->ctx, sizeof(struct _muacc_ctx));

	_ctx->bind_sa_req   = _muacc_clone_sockaddr(src->ctx->bind_sa_req, src->ctx->bind_sa_req_len);
	_ctx->bind_sa_suggested   = _muacc_clone_sockaddr(src->ctx->bind_sa_suggested, src->ctx->bind_sa_suggested_len);

	_ctx->remote_addrinfo_hint = _muacc_clone_addrinfo(src->ctx->remote_addrinfo_hint);
	_ctx->remote_addrinfo_res  = _muacc_clone_addrinfo(src->ctx->remote_addrinfo_res);

	_ctx->remote_hostname = _muacc_clone_string(src->ctx->remote_hostname);

	_ctx->sockopts_current = _muacc_clone_socketopts(src->ctx->sockopts_current);
	_ctx->sockopts_suggested = _muacc_clone_socketopts(src->ctx->sockopts_suggested);

	_ctx->ctxid[0] += 1;

=======
>>>>>>> pipelining*/
	dst->usage = 1;
	dst->locks = 0;
	dst->mamsock = -1;

	return(0);
}



int _muacc_connect_ctx_to_mam(muacc_context_t *ctx)
{
	struct sockaddr_un mams;
	mams.sun_family = AF_UNIX;
	#ifdef HAVE_SOCKADDR_LEN
	mams.sun_len = sizeof(struct sockaddr_un);
	#endif

	if(	ctx->mamsock != -1 )
		return 0;

	strncpy( mams.sun_path, MUACC_SOCKET, sizeof(mams.sun_path));
	ctx->mamsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(ctx->mamsock == -1)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: socket creation failed: %s\n", strerror(errno));
		return(-errno);
	}

	if(connect(ctx->mamsock, (struct sockaddr*) &mams, sizeof(mams)) < 0)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: connect to mam via %s failed: %s\n",  mams.sun_path, strerror(errno));
		close(ctx->mamsock);
		ctx->mamsock = -1;
		return(-errno);
	}

	return 0;
}


int _muacc_contact_mam (muacc_mam_action_t reason, muacc_context_t *ctx)
{

	char buf[MUACC_TLV_MAXLEN];
	ssize_t pos = 0;
	ssize_t ret = 0;
	muacc_tlv_t tag;
	void *data;
	ssize_t data_len;

	/* connect to MAM */
	if(	_muacc_connect_ctx_to_mam(ctx) != 0 )
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: failed to contact MAM\n");
		goto _muacc_contact_mam_connect_err;
	}

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Serializing MAM context\n");

	/* pack request */
	if( 0 > _muacc_push_tlv(buf, &pos, sizeof(buf), action, &reason, sizeof(muacc_mam_action_t)) ) goto  _muacc_contact_mam_pack_err;
	if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), ctx->ctx) ) goto  _muacc_contact_mam_pack_err;
	if( 0 > _muacc_push_tlv_tag(buf, &pos, sizeof(buf), eof) ) goto  _muacc_contact_mam_pack_err;
	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2,"Serializing MAM context done - Sending it to MAM\n");


	/* send request */
	if( 0 > (ret = send(ctx->mamsock, buf, pos, 0)) )
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: error sending request: %s\n", strerror(errno));
		goto _muacc_contact_mam_connect_err;
	}
	else
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Request sent  - %ld of %ld bytes\n", (long int) ret, (long int) pos);
	}

	/* read & unpack response */
	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Processing response \n");
	pos = 0;
	while( (ret = _muacc_read_tlv(ctx->mamsock, buf, &pos, sizeof(buf), &tag, &data, &data_len)) > 0)
	{
		if( tag == eof )
			break;
		else if ( 0 > _muacc_unpack_ctx(tag, data, data_len, ctx->ctx) )
			goto  _muacc_contact_mam_parse_err;
	}
	return(0);

_muacc_contact_mam_connect_err:
	return(-1);

_muacc_contact_mam_pack_err:

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: failed to serialize MAM context\n");
	return(-1);

_muacc_contact_mam_parse_err:

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: failed to process response\n");
	return(-1);

}

int muacc_set_intent(socketopt_t **opts, int optname, const void *optval, socklen_t optlen, int flags)
{
	return _muacc_add_sockopt_to_list(opts, SOL_INTENTS, optname, optval, optlen, flags);
}

int muacc_free_socket_option_list(struct socketopt *opts)
{
	if (opts != 0)
	{
		_muacc_free_socketopts(opts);
		return 0;
	}

	return -1;
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
				*list_of_sets = (*list_of_sets)->next;
			}
			(*list_of_sets)->next = newset;
		}
		return newset;
	}
	else
	{
		pthread_rwlock_wrlock(&(set->lock));
		DLOG(CLIB_IF_LOCKS, "LOCK: Adding new socket to set - Locking %p\n", (void *) set);

		if (set->sockets != NULL)
		{
			/* Add socket to existing socket set */
			struct socketlist *slist = set->sockets;

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
		}
		else
		{
			/* Add socket to empty socket set */
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket set was empty - adding %d to it\n", socket);

			set->sockets = malloc(sizeof(struct socketset));
			if (set->sockets == NULL)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Could not allocate memory for set of socket %d!\n", socket);
				return NULL;
			}
			set->sockets->next = NULL;
			set->sockets->file = socket;
			set->sockets->flags = 0;
			set->sockets->flags |= MUACC_SOCKET_IN_USE;
			set->use_count += 1;
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Added %d - Use count of socket set is now %d\n", socket, set->use_count);
			set->sockets->ctx = _muacc_clone_ctx(ctx);
		}
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
		if (list_of_sets->type == ctx->type && (strncmp(list_of_sets->host, ctx->remote_hostname, list_of_sets->hostlen) == 0) && (strncmp(list_of_sets->serv, ctx->remote_service, list_of_sets->servlen) == 0))
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

void muacc_print_socketsetlist(struct socketset *list_of_sets)
{
	pthread_rwlock_rdlock(&socketsetlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Printing socketsetlist - Getting global lock\n");
	dprintf(muacc_debug_fd, "\n\t\tList of Socketsets:\n{ ");
	while (list_of_sets != NULL)
	{
		muacc_print_socketset(list_of_sets);
		dprintf(muacc_debug_fd, "} <next socket set...>\n");

		list_of_sets = list_of_sets->next;
	}
	dprintf(muacc_debug_fd, "}\n\n");
	pthread_rwlock_unlock(&socketsetlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Printed socketsetlist - Released global lock\n");
}

void muacc_print_socketset(struct socketset *set)
{
	DLOG(CLIB_IF_LOCKS, "LOCK: Printing socket set - Locking %p\n", (void *) set);
	pthread_rwlock_rdlock(&(set->lock));
	dprintf(muacc_debug_fd, "{ ");
	dprintf(muacc_debug_fd, "host = %s\n", (set->host == NULL ? "(null)" : set->host));
	dprintf(muacc_debug_fd, "serv = %s\n", (set->serv == NULL ? "(null)" : set->serv));
	dprintf(muacc_debug_fd, "type = %d\n", set->type);
	dprintf(muacc_debug_fd, "use_count = %d\n", set->use_count);
	struct socketlist *list = set->sockets;
	while (list != NULL)
	{
		strbuf_t sb;
		strbuf_init(&sb);

		dprintf(muacc_debug_fd, "{ file = %d\n", list->file);
		dprintf(muacc_debug_fd, "flags = %d\n", list->flags);
		dprintf(muacc_debug_fd, "ctx = ");
		_muacc_print_ctx(&sb, list->ctx);
		dprintf(muacc_debug_fd, "%s", strbuf_export(&sb));
		strbuf_release(&sb);

		list = list->next;
		dprintf(muacc_debug_fd, "} ");
	}
	pthread_rwlock_unlock(&(set->lock));
	DLOG(CLIB_IF_LOCKS, "LOCK: Finished printing - Unlocked %p\n", (void *) set);
}

int _muacc_send_socketchoose (muacc_context_t *ctx, int *socket, struct socketset *set)
{
	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Sending socketchoose\n");
	int returnvalue = -1;

	char buf[MUACC_TLV_MAXLEN];
	ssize_t pos = 0;
	ssize_t ret = 0;
	muacc_tlv_t tag;
    void *data;
    ssize_t data_len;

	muacc_mam_action_t reason = muacc_act_socketchoose_req;

	struct socketlist *list = set->sockets;
    struct socketlist *prev = NULL;

	if ( _muacc_connect_ctx_to_mam(ctx) != 0 )
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "WARNING: failed to contact MAM\n");
        goto unlock_set;
	}

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Serializing MAM context\n");
	if ( 0 > _muacc_push_tlv(buf, &pos, sizeof(buf), action, &reason, sizeof(muacc_mam_action_t)) )
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error pushing label\n");
		goto unlock_set;
	}

	/* Pack context from request */
	if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), ctx->ctx) )
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error serializing socket context \n");
		goto unlock_set;
	}

	/* Pack sockets from socketset */
	while (list != NULL)
	{
        /* Only consider sockets that are not remotly closed (FIN,ACK received) */
        if (_is_socket_open(list->file))
        {
            /* Suggest all sockets that are currently not in use to MAM */
            if ((list->flags & MUACC_SOCKET_IN_USE) == 0)
            {
                DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Pushing socket %d\n", list->file);
                if ( 0 > _muacc_push_tlv(buf, &pos, sizeof(buf), socketset_file, &(list->file), sizeof(int)) )
                {
                    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error pushing socket with file descriptor %d\n", list->file);
                    goto unlock_set;
                }
                if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), list->ctx) )
                {
                    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error pushing socket context of %d\n", list->file);
                    goto unlock_set;
                }
            }
        }
        else
        {
            /* Close remotely closed socket */
            DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Closing remotely closed socket = %d\n", list->file);
            if (1 == _muacc_free_socket(set, list, prev))
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket set is empty now!\n");
				set->sockets = NULL;
			}
        }
        
        prev = list;
        list = list->next;
        
	}
	if( 0 > _muacc_push_tlv_tag(buf, &pos, sizeof(buf), eof) )
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error pushing eof\n");
		goto unlock_set;
	}
    
	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Pushing request done\n");
	DLOG(CLIB_IF_LOCKS, "LOCK: Pushed socket set - Unlocking %p\n", (void *)set);
	pthread_rwlock_unlock(&(set->lock));

	if ( 0 > (ret = send(ctx->mamsock, buf, pos, 0)) )
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error sending request: %s\n", strerror(errno));
		return -1;
	}
	else
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Sent request - %ld of %ld bytes\n", (long int) ret, (long int) pos);
	}

	/* read & unpack response */
    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Getting response:\n");
    pos = 0;
	int ret2 = -1;
	int set_in_use = 0;

    while( (ret = _muacc_read_tlv(ctx->mamsock, buf, &pos, sizeof(buf), &tag, &data, &data_len)) > 0)
    {
		if (tag == action)
		{
			if (*(muacc_mam_action_t *) data == muacc_act_socketchoose_resp_existing)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "MAM says: Use existing socket!\n");

				pthread_rwlock_wrlock(&(set->lock));
				DLOG(CLIB_IF_LOCKS, "LOCK: Checking socketset %p - Locking it\n", (void *)set);

				set_in_use = 1;
			}
			else if (*(muacc_mam_action_t *) data == muacc_act_socketchoose_resp_new)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "MAM says: Open a new socket!\n");
				*socket = -1;
				returnvalue = 1;
			}
			else if (*(muacc_mam_action_t *) data == muacc_error_resolve)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error: Name resolution failed.\n");
				return -1;
			}
			else if (*(muacc_mam_action_t *) data == muacc_error_unknown_request)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error: MAM sent error code \"Unknown Request\" -- Aborting.\n");
				return -1;
			}
			else
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error: Unknown MAM Response Action Type %d\n", *(muacc_mam_action_t *) data);
				return -1;
			}
		}
		else if (tag == socketset_file && data_len == sizeof(int))
		{
			if (set_in_use)
			{
                prev = NULL;
				list = set->sockets;
				while (list != NULL && list->file != *(int *) data)
				{
                    prev = list;
					list = list->next;
				}

				if (list == NULL)
				{
					DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d suggested, but not found in set.\n", *(int *)data);
					*socket = -1;
					returnvalue = 1;
				}
				else if ((list->flags & MUACC_SOCKET_IN_USE) == 0)
				{
					// Socket is not in use yet - set flag as IN USE
					list->flags |= MUACC_SOCKET_IN_USE;
					set->use_count += 1;
					DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Use socket %d - use count of set is now %d\n", *socket, set->use_count);
					memcpy(socket, (int *)data, data_len);
					DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Use socket %d from set - mark it as \"in use\" and returning\n", *socket);
                    
                    if (!_is_socket_open(list->file))
                    {
                        _muacc_free_socket(set, list, prev);
                        DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket closed on remote side - closed it! socket = %d", list->file);
                        continue;
                    }

					DLOG(CLIB_IF_LOCKS, "LOCK: Found socket to use - Unlocking socketset lock\n");
					pthread_rwlock_unlock(&(set->lock));
					return 0;
				}
				else
				{
					// Socket is already in use, so we cannot use it
					DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d suggested, but is already in use.\n", *(int *) data);
					*socket = -1;
					returnvalue = 1;
				}
			}
			else
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d suggested, but list not locked -- fail\n", *(int *)data);
				*socket = -1;
				returnvalue = 1;
			}
		}
        else if( tag == eof )
            break;
        else
		{
			ret2 = _muacc_unpack_ctx(tag, data, data_len, ctx->ctx);
			if ( 0 > ret2 )
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error unpacking context\n");

				if (set_in_use)
				{
					DLOG(CLIB_IF_LOCKS, "LOCK: End of socketchoose - Unlocking set %p\n", (void *)set);
					pthread_rwlock_unlock(&(set->lock));
				}

				return -1;
			}
		}
    }
    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Socketchoose done, returnvalue = %d, socket = %d\n", returnvalue, *socket);

	if (set_in_use)
	{
    
unlock_set:
		DLOG(CLIB_IF_LOCKS, "LOCK: End of socketchoose - Unlocking set %p\n", (void *)set);
		pthread_rwlock_unlock(&(set->lock));
	}
	return returnvalue;
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
		if (currentlist == NULL)
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "DEL %d: Socketset is already empty!\n", socket);
			return -1;
		}

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

int _muacc_host_serv_to_ctx(muacc_context_t *ctx, const char *host, size_t hostlen, const char *serv, size_t servlen)
{
	if (host == NULL || serv == NULL)
    {
        DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Host or service not given - aborting.\n");
        return -1;
    }
    else
    {
        DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Writing hostname %s and service %s to context\n", host, serv);
        ctx->ctx->remote_addrinfo_hint = malloc(sizeof(struct addrinfo));
        memset(ctx->ctx->remote_addrinfo_hint, 0, sizeof(struct addrinfo));
        ctx->ctx->remote_addrinfo_hint->ai_family = ctx->ctx->domain;
        ctx->ctx->remote_addrinfo_hint->ai_socktype = ctx->ctx->type;
        ctx->ctx->remote_addrinfo_hint->ai_protocol = ctx->ctx->protocol;

        ctx->ctx->remote_hostname = malloc(hostlen + 1);
        ctx->ctx->remote_hostname[hostlen] = 0;
        ctx->ctx->remote_hostname = strncpy(ctx->ctx->remote_hostname, host, hostlen);

		struct servent *service = getservbyname(serv, NULL);
		// check if the serv is already the port number given as string
		if (service == NULL)
        {
          double servnb_h = strtod(serv, NULL);
          int servnb_n = (int) htons(servnb_h);
          DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, " \t This is the casted int port number: %d \n", servnb_n);
          service = getservbyport(servnb_n, NULL);
          if(service== NULL) DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, " \t getservbyport couldn't resolve port \n");
		}

		if (service != NULL)
		{
			int port = ntohs(service->s_port);
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0,"Resolved Service name %s to port number %d\n", serv, port);
			asprintf(&(ctx->ctx->remote_service), "%d", port);
		}
		else
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Warning: Could not convert service name %s to port number\n", serv);
			ctx->ctx->remote_service = malloc(servlen + 1);
			ctx->ctx->remote_service[servlen] = 0;
			ctx->ctx->remote_service = strncpy(ctx->ctx->remote_service, serv, servlen);
		}

        DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Wrote hostname %s and service %s to context\n", ctx->ctx->remote_hostname, ctx->ctx->remote_service);
	}
	return 0;
}

int _muacc_free_socket(struct socketset *set_to_delete, struct socketlist *socket_to_delete, struct socketlist *prevlist)
{
	int returnvalue = -1;
	int socketfd = socket_to_delete->file;

	// Free context if no other file descriptor needs it
	if (_muacc_socketset_find_dup(socket_to_delete) == NULL)
	{
		// No duplicate (i.e., no other file descriptor shares this socket/context)
		_muacc_free_ctx(socket_to_delete->ctx);
	}

	// Re-adjust pointers
	if (prevlist != NULL)
	{
		// This is not the first socket of the set
		prevlist->next = socket_to_delete->next;
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: Readjusted set pointers\n", socket_to_delete->file);
		returnvalue = 0;
	}
	else
	{
		// This IS the first socket of the set
		if (socket_to_delete->next != NULL)
		{
			// There are more sockets in the set
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: This is the first socket in the set - readjusting pointer\n", socket_to_delete->file);
			set_to_delete->sockets = socket_to_delete->next;
			returnvalue = 0;
		}
		else
		{
			// This was the only socket in the set - clear this set
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "DEL %d: This is the ONLY socket in the set - need to free set\n", socket_to_delete->file);
			returnvalue = 1;
		}
		free(socket_to_delete);
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
