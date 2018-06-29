/** \file muacc_client_util.c
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
#include <fcntl.h>

#include "dlog.h"
#include "muacc_ctx.h"
#include "muacc_tlv.h"
#include "intents.h"

#include "client_util.h"
#include "client_socketapi.h"
#include "muacc_util.h"
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
	ssize_t ret;
	int flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
 	ret = recv(sockfd, &dummy, 1, MSG_PEEK );
	fcntl(sockfd, F_SETFL, flags );

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket closed check returned: %zu errno: %d\n", ret, errno);
	if (ret == 0)
	{
		return 0;
	}
	else if (ret == -1)
	{
		if (errno == EWOULDBLOCK)
			return 1;
		else
			return 0;
	}
	else
		return 1;
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

int _muacc_send_socketchoose (muacc_context_t *ctx, int *socket, struct socketset *set)
{
	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Sending socketchoose\n");
	int returnvalue = -1;

	char buf[MUACC_TLV_MAXLEN];
	ssize_t pos = 0;
	ssize_t prevpos = 0;
	ssize_t ret = 0;
	muacc_tlv_t tag;
    void *data;
    ssize_t data_len;

	muacc_mam_action_t reason = muacc_act_socketchoose_req;

	struct socketlist *list = set->sockets;
    struct socketlist *prev = NULL;
	struct socketlist *list_next = NULL;

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
                // Store current position in buffer, in case adding this socket fails
                prevpos = pos;

                DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Pushing socket %d to buf %p pos %li\n", list->file, buf, pos);
                if ( 0 > _muacc_push_tlv(buf, &pos, sizeof(buf), socketset_file, &(list->file), sizeof(int)) )
                {
                    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error pushing socket with file descriptor %d\n", list->file);
                    // Abort adding this socket to the request, just add eof and send it
                    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Resetting pos to %li and trying to push eof\n", prevpos);
                    pos = prevpos;
                    goto push_eof;
                }
                if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), list->ctx) )
                {
                    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error pushing socket context of %d\n", list->file);
                    // Abort adding this socket to the request, just add eof and send it
                    DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Resetting pos to %li and trying to push eof\n", prevpos);
                    pos = prevpos;
                    goto push_eof;
                }
            }
			prev = list;
			list = list->next;
        }
        else
        {
			list_next = list->next;

            /* Close remotely closed socket */
            DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Closing remotely closed socket = %d\n", list->file);
            if (1 == _muacc_free_socket(set, list, prev))
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket set is empty now!\n");
				set->sockets = NULL;
			}
			list = list_next;
        }
        
	}
push_eof:
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
                        if(1 == _muacc_free_socket(set, list, prev))
						{
							DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket set is empty now!\n");
							set->sockets = NULL;
						}
                        DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket closed on remote side - closed it! socket = %d\n", list->file);
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

int _muacc_socketconnect_create(muacc_context_t *ctx, int *s, struct socketset **my_socketsetlist, pthread_rwlock_t *my_socketsetlist_lock, int create_nonblock_socket)
{
	if (ctx == NULL || s == NULL)
		return -1;

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Creating socket (Domain: %d, Type: %d, Protocol: %d)\n", ctx->ctx->domain, ctx->ctx->type, ctx->ctx->protocol);
	if ((*s = socket(ctx->ctx->domain, ctx->ctx->type, ctx->ctx->protocol)) != -1)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Successfully created socket %d\n", *s);
	}
	else
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	if(create_nonblock_socket) {
		/* Set O_NONBLOCK flag on the socket */
		fcntl(*s, F_SETFL, fcntl(*s, F_GETFL, 0) | O_NONBLOCK);
	}

	DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Setting suggested socket options\n");
	if (MUACC_CLIENT_UTIL_NOISY_DEBUG2)
	{
		printf("Socket options:\n");
		_muacc_print_socket_option_list(ctx->ctx->sockopts_suggested);
	}

	struct socketopt *so = NULL;
	for (so = ctx->ctx->sockopts_suggested; so != NULL; so = so->next)
	{
		so->returnvalue = muacc_sa_setsockopt(ctx, *s, so->level, so->optname, so->optval, so->optlen);
		if (so->returnvalue == -1)
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Setting sockopt failed: %s\n", strerror(errno));
			if (so->flags && SOCKOPT_OPTIONAL != 0)
			{
				// fail
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket option was mandatory, but failed - returning\n");
				return -1;
			}
		}
		else
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket option was set successfully\n");
			so->flags &= SOCKOPT_IS_SET;
		}

	}

	if (ctx->ctx->bind_sa_suggested != NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Attempting to bind socket %d\n", *s);
		if (MUACC_CLIENT_UTIL_NOISY_DEBUG2)
		{
			printf("Local address:\n");
			_muacc_print_socket_addr(ctx->ctx->bind_sa_suggested, ctx->ctx->bind_sa_suggested_len);
			printf("\n");
		}

		if (0 == bind(*s, ctx->ctx->bind_sa_suggested, ctx->ctx->bind_sa_suggested_len))
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Bound socket %d to suggested local address\n", *s);
		}
		else
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Error binding socket %d to local address: %s\n", *s, strerror(errno));
			return -1;
		}
	}

	if (ctx->ctx->remote_sa == NULL)
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d got no remote address to connect to - fail\n", *s);
		return -1;
	}
	else
	{
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Attempting to connect socket %d\n", *s);
		if (MUACC_CLIENT_UTIL_NOISY_DEBUG2)
		{
			printf("Remote address:\n");
			_muacc_print_socket_addr(ctx->ctx->remote_sa, ctx->ctx->remote_sa_len);
			printf("\n");
		}

		if (0 != connect(*s, ctx->ctx->remote_sa, ctx->ctx->remote_sa_len))
		{
			if(errno==EINPROGRESS && create_nonblock_socket)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d non-blocking connect is now in progress.\n", *s);
			}
			else
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d Connection failed: %s\n", *s, strerror(errno));
				return -1;
			}
		}
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG0, "Successfully created and connected socket %d\n", *s);
		DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Adding %d to list.\n", *s);

		if(my_socketsetlist_lock)
		{
			pthread_rwlock_wrlock(my_socketsetlist_lock);
			DLOG(CLIB_IF_LOCKS, "LOCK: Adding socket to a socket set - Got global lock\n");
		}
		struct socketset *set = _muacc_add_socket_to_set(my_socketsetlist, *s, ctx->ctx);
		if(my_socketsetlist_lock)
		{
			DLOG(CLIB_IF_LOCKS, "LOCK: Tried to add socket to a socket set - Unlocking global lock\n");
			pthread_rwlock_unlock(my_socketsetlist_lock);
		}
		if (set != NULL)
		{
			if (MUACC_CLIENT_UTIL_NOISY_DEBUG2)
			{
				DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG2, "Socket %d was successfully added:\n", *s);
				/* muacc_print_socketset(set); */
			}
		}
		else
		{
			DLOG(MUACC_CLIENT_UTIL_NOISY_DEBUG1, "Socket %d could not be added!\n", *s);
		}
		return 1;
	
	}
}
