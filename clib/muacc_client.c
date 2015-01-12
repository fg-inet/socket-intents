#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "dlog.h"

#include "lib/intents.h"

#include "muacc_client_util.h"

#ifndef CLIB_IF_NOISY_DEBUG0
#define CLIB_IF_NOISY_DEBUG0 1
#endif

#ifndef CLIB_IF_NOISY_DEBUG1
#define CLIB_IF_NOISY_DEBUG1 0
#endif

#ifndef CLIB_IF_NOISY_DEBUG2
#define CLIB_IF_NOISY_DEBUG2 0
#endif

#ifndef CLIB_IF_LOCKS
#define CLIB_IF_LOCKS 0
#endif

struct socketlist *sockets = NULL;
pthread_rwlock_t socketlist_lock = PTHREAD_RWLOCK_INITIALIZER;

int muacc_socket(muacc_context_t *ctx,
        int domain, int type, int protocol)
{
	int ret = -2;

	DLOG(CLIB_IF_NOISY_DEBUG2, "invoked\n");

	if( ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "NULL context - fallback to regular socket\n");
		goto muacc_socket_fallback;
	}
	else if( ctx->ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - trying to initialize\n");
		muacc_init_context(ctx);
		if( ctx->ctx == NULL )
			goto muacc_socket_fallback;
	}

	if( _lock_ctx(ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular socket\n");
		_unlock_ctx(ctx);
		goto muacc_socket_fallback;
	}

	ctx->ctx->calls_performed |= MUACC_SOCKET_CALLED;
	ctx->ctx->domain = domain;
	ctx->ctx->type = type;
	ctx->ctx->protocol = protocol;

	ret = socket(domain, type, protocol);
    
    ctx->ctx->ctxino = _muacc_get_ctxino(ret);

	_unlock_ctx(ctx);
	return ret;

	muacc_socket_fallback:

	return socket(domain, type, protocol);
}

int muacc_getaddrinfo(muacc_context_t *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res)
{

	int ret;

	DLOG(CLIB_IF_NOISY_DEBUG2, "invoked\n");

	/* check context and initialize if neccessary */
	if(ctx == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "NULL context - fallback to regular connect\n");
		goto muacc_getaddrinfo_fallback;
	}
	else if( ctx->ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - trying to initialize\n");
		muacc_init_context(ctx);
		if( ctx->ctx == NULL )
			goto muacc_getaddrinfo_fallback;
	}

	if( _lock_ctx(ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular connect\n");
		_unlock_ctx(ctx);
		goto muacc_getaddrinfo_fallback;
	}
	
	/* flag call performed */
	ctx->ctx->calls_performed |= MUACC_GETADDRINFO_CALLED;
	
	/* save hostname */
	if(ctx->ctx->remote_hostname != NULL)
		free(ctx->ctx->remote_hostname);
	ctx->ctx->remote_hostname = _muacc_clone_string(hostname);

	/* save hint */
	if(ctx->ctx->remote_addrinfo_hint != NULL)
		freeaddrinfo(ctx->ctx->remote_addrinfo_hint);
	ctx->ctx->remote_addrinfo_hint = _muacc_clone_addrinfo(hints);

	/* clear result from previous calls */
	if (ctx->ctx->remote_addrinfo_res != NULL)
	{
		ctx->ctx->remote_addrinfo_res = NULL;
	}

	DLOG(CLIB_IF_NOISY_DEBUG2, "contacting mam\n");

	/* contact mam */
	_muacc_contact_mam(muacc_act_getaddrinfo_resolve_req, ctx);

	if(ctx->ctx->remote_addrinfo_res != NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "using result from mam\n");
		
		*res = _muacc_clone_addrinfo(ctx->ctx->remote_addrinfo_res);
		ret = 0;
	}
	else
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "no result from mam - resolving name on my own\n");
		
		/* do query on our own */
		ret = 	 getaddrinfo(hostname, servname, hints, res);
		if (ret == 0)
		{
			/* save response */
			ctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(*res);

		}
	}

	_unlock_ctx(ctx);

	return ret;

muacc_getaddrinfo_fallback:

	return getaddrinfo(hostname, servname, hints, res);

}


int muacc_setsockopt(muacc_context_t *ctx, int socket, int level, int option_name,
    const void *option_value, socklen_t option_len)
{
	int retval = -2; // Return value; will be set, else structure problem in function

	/* check context and initialize if neccessary */
	if( ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "NULL context - fallback to regular setsockopt\n");
		goto muacc_setsockopt_fallback;
	}
	else if( ctx->ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - trying to initialize\n");
		muacc_init_context(ctx);
		if( ctx->ctx == NULL )
			goto muacc_setsockopt_fallback;
	}

	if( _lock_ctx(ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular setsockopt\n");
		_unlock_ctx(ctx);
		goto muacc_setsockopt_fallback;
	}

	if (level == SOL_INTENTS)
	{
		// Intent socket options are handled by us
		if (option_value == NULL)
		{
			// Invalid buffer
			errno = EFAULT;
			_unlock_ctx(ctx);
			return -1;
		}
	}
	else
	{
		// Socket option not an intent: Call original setsockopt function
		if ((retval = setsockopt(socket, level, option_name, option_value, option_len)) < 0)
		{
			_unlock_ctx(ctx);
			return retval;
		}

		retval = 0;
	}

	/* we have set successfully an socket option or checked an intend - save for MAM */

	/* Go through sockopt list and look for this option */

	retval = _muacc_add_sockopt_to_list(&(ctx->ctx->sockopts_current), level, option_name, option_value, option_len, 0);

	_unlock_ctx(ctx);

	return retval;

	muacc_setsockopt_fallback:

	return setsockopt(socket, level, option_name, option_value, option_len);

}

int muacc_getsockopt(muacc_context_t *ctx, int socket, int level, int option_name,
    void *option_value, socklen_t *option_len)
{
	int retval = -2; // Return value, will be set, else structure problem in function

	if( ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "NULL context - fallback to regular getsockopt\n");
		return getsockopt(socket, level, option_name, option_value, option_len);
	}
	else if( ctx->ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - trying to initialize\n");
		muacc_init_context(ctx);
		if( ctx->ctx == NULL )
			return getsockopt(socket, level, option_name, option_value, option_len);
	}

	if( _lock_ctx(ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular getsockopt\n");
		_unlock_ctx(ctx);
		return getsockopt(socket, level, option_name, option_value, option_len);
	}

	if( level == SOL_INTENTS)
	{
		// Intent socket options are handled by us
		if (option_value == NULL || option_len == NULL)
		{
			// Invalid buffer
			errno = EFAULT;
			_unlock_ctx(ctx);
			return -1;
		}

		DLOG(CLIB_IF_NOISY_DEBUG2, "Looking for socket option: \n\t\t\t{ { level = %d, optname = %d, value %p } }\n", level, option_name, option_value);

		struct socketopt *current = ctx->ctx->sockopts_current;
		while (current != NULL)
		{
			// Search for the option_name in this contexts' socket_option list
			if (current->optname == option_name)
			{
				// Found it!
				if ((memcpy(option_value, current->optval, current->optlen) == NULL) || (memcpy(option_len, &current->optlen, sizeof(size_t)) == NULL))
				{
					// Error copying data
					errno = EFAULT;
					retval = -1;
				}
				else
				{
					// Successfully copied data: End loop
					DLOG(CLIB_IF_NOISY_DEBUG2, "Found socket option: \n\t\t\t");
					if (CLIB_IF_NOISY_DEBUG2) _muacc_print_socket_option_list(current);

					retval = 0;
					break;
				}
			}
			current = current->next;
		}
		if (current == NULL)
		{
			// Reached end of list without finding the option
			errno = ENOPROTOOPT;
			retval = -1;
		}
	}
	else
	{
		// Requested socket option is not on 'intents' layer
		if ((retval = getsockopt(socket, level, option_name, option_value, option_len)) < 0)
		{
			_unlock_ctx(ctx);
			return retval;
		}
	}

	// If we arrive here, we have successfully gotten the option (intent or other)

	_unlock_ctx(ctx);

	return retval;
}

int muacc_bind(muacc_context_t *ctx, int socket, const struct sockaddr *address, socklen_t address_len)
{
	int ret = -1;

	DLOG(CLIB_IF_NOISY_DEBUG2, "invoked\n");

	if( ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "NULL context - fallback to regular connect\n");
		goto muacc_bind_fallback;
	}
	else if( ctx->ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - trying to initialize\n");
		muacc_init_context(ctx);
		if( ctx->ctx == NULL )
			goto muacc_bind_fallback;
	}

	if( _lock_ctx(ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular connect\n");
		_unlock_ctx(ctx);
		goto muacc_bind_fallback;
	}

	ctx->ctx->calls_performed |= MUACC_BIND_CALLED;
	ret = bind(socket, address, address_len);

	if (ret == 0)
	{
		ctx->ctx->bind_sa_req = _muacc_clone_sockaddr(address, address_len);
		ctx->ctx->bind_sa_req_len = address_len;
	}
	_unlock_ctx(ctx);
	return ret;

	muacc_bind_fallback:

	return bind(socket, address, address_len);

}

int muacc_connect(muacc_context_t *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len)
{
	struct socketopt *so = NULL;
	int retval;

	DLOG(CLIB_IF_NOISY_DEBUG2, "invoked\n");

	if( ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "NULL context - fallback to regular connect\n");
		goto muacc_connect_fallback;
	}
	else if( ctx->ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - trying to initialize\n");
		muacc_init_context(ctx);
		if( ctx->ctx == NULL )
			goto muacc_connect_fallback;
	}

	if( _lock_ctx(ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular connect\n");
		_unlock_ctx(ctx);
		goto muacc_connect_fallback;
	}

	ctx->ctx->calls_performed |= MUACC_CONNECT_CALLED;

	ctx->ctx->remote_sa     = _muacc_clone_sockaddr((struct sockaddr *)address, address_len);
	ctx->ctx->remote_sa_len = address_len;

	ctx->ctx->domain = address->sa_family;

	if( _muacc_contact_mam(muacc_act_connect_req, ctx) <0 ){
		_unlock_ctx(ctx);
		DLOG(CLIB_IF_NOISY_DEBUG0, "got no response from mam - fallback to regular connect\n");
		goto muacc_connect_fallback;
	}

	/* bind if no request but the mam suggestion exists */
	if ( ctx->ctx->bind_sa_req == NULL && ctx->ctx->bind_sa_suggested != NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "trying to bind with mam-supplied data\n");
		if( bind(socket, ctx->ctx->bind_sa_suggested, ctx->ctx->bind_sa_suggested_len) != 0 )
		{
			DLOG(CLIB_IF_NOISY_DEBUG0, "error binding with mam-supplied data: %s\n", strerror(errno));
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "binding with mam-supplied data succeeded\n");
		}
	}

	/* set socketopts */
	for(so = ctx->ctx->sockopts_suggested; so != NULL; so = so->next)
	{
		strbuf_t sb;
		strbuf_init(&sb);

		if (so->level == SOL_INTENTS)
		{
			/* skip option */
			DLOG(CLIB_IF_NOISY_DEBUG1, "skipping suggested SOL_INTENTS socketopt\n");
			continue;
		}

		#ifdef CLIB_IF_NOISY_DEBUG1
		strbuf_rewind(&sb); _muacc_print_socket_option(&sb, so);
		DLOG(CLIB_IF_NOISY_DEBUG1, "trying to setting suggested socketopt %s\n", strbuf_export(&sb));
		#endif

		if ( (retval = setsockopt(socket, so->level, so->optname, so->optval, so->optlen)) == -1 )
		{
			strbuf_rewind(&sb); _muacc_print_socket_option(&sb, so);
			DLOG(CLIB_IF_NOISY_DEBUG0, "setting suggested socketopt %s failed: %s\n", strbuf_export(&sb), strerror(errno));
		}
		strbuf_release(&sb);
	}

	/* unlock context and do request */
	_unlock_ctx(ctx);

	return connect(socket, ctx->ctx->remote_sa, ctx->ctx->remote_sa_len);


muacc_connect_fallback:

	return connect(socket, address, address_len);

}

int muacc_close(muacc_context_t *ctx,
        int socket)
{
	int ret = -2;
	ctx->ctx->calls_performed |= MUACC_CLOSE_CALLED;

	DLOG(CLIB_IF_NOISY_DEBUG2, "invoked\n");

	if( ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "NULL context - fallback to regular close\n");
		goto muacc_close_fallback;
	}
	else if( ctx->ctx == NULL )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized\n");
		goto muacc_close_fallback;
	}

	if( _lock_ctx(ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular close\n");
		_unlock_ctx(ctx);
		goto muacc_close_fallback;
	}

	ret = close(socket);

	/* Release and deinitialize context */
	if (0 == muacc_release_context(ctx))
		ctx->ctx = NULL;
	
	_unlock_ctx(ctx);

	return ret;

	muacc_close_fallback:

	return close(socket);
}

int socketconnect(int *s, const char *url, struct socketopt *sockopts, int domain, int type, int proto)
{
	DLOG(CLIB_IF_NOISY_DEBUG0, "Socketconnect invoked, socket: %d\n", *s);
	if (s == NULL)
		return -1;

	muacc_context_t ctx;
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

	if (*s == -1)
	{
		/* Socket does not exist yet - create it */
		int ret;

		if ((ret = _socketconnect_request(&ctx, s, url)) == -1)
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
		/* Socket exists - Search for corresponding socket set */
		struct socketlist *slist;
		int ret;

		pthread_rwlock_wrlock(&socketlist_lock);
		DLOG(CLIB_IF_LOCKS, "LOCK: Got global lock\n");
		if ((slist = _muacc_find_socketlist(sockets, *s)) != NULL)
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Found Socket Set\n");
			if (_muacc_parse_url_to_ctx(&ctx, url) != 0)
			{
				DLOG(CLIB_IF_NOISY_DEBUG2, "No URL given this time - trying to take the one from the set\n");
				_muacc_parse_url_to_ctx(&ctx, slist->set->ctx->remote_hostname);
			}
		}
		else
		{
			DLOG(CLIB_IF_LOCKS, "LOCK: Set not found - Unlocking global lock\n");
			pthread_rwlock_unlock(&socketlist_lock);
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socket not in set - creating new one.\n");
			if ((ret = _socketconnect_request(&ctx, s, url)) == -1)
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

		if ((ret = _socketchoose_request (&ctx, s, slist)) == -1)
		{
			DLOG(CLIB_IF_LOCKS, "LOCK: Socketchoose error - Unlocking global lock\n");
			pthread_rwlock_unlock(&socketlist_lock);
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socketchoose error!\n");
			muacc_release_context(&ctx);
			return -1;
		}
		else if (ret == 1)
		{
			DLOG(CLIB_IF_LOCKS, "LOCK: Opened new socket - Unlocking global lock\n");
			pthread_rwlock_unlock(&socketlist_lock);
			DLOG(CLIB_IF_NOISY_DEBUG2, "Successfully opened new socket.\n");
			muacc_release_context(&ctx);
			return 1;
		}
		else
		{
			DLOG(CLIB_IF_LOCKS, "LOCK: Chose existing socket - Unlocking global lock\n");
			pthread_rwlock_unlock(&socketlist_lock);
			DLOG(CLIB_IF_NOISY_DEBUG2, "Successfully chose existing socket.\n");
			muacc_release_context(&ctx);
			return 0;
		}
	}
}

int _socketconnect_request(muacc_context_t *ctx, int *s, const char *url)
{
	if (ctx == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "No context given - aborting.\n");
		return -1;
	}
	else if (_muacc_parse_url_to_ctx(ctx, url) != 0)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Could not parse URL - aborting.\n");
		return -1;
	}
	else
	{
		if (CLIB_IF_NOISY_DEBUG2)
		{
			printf("Before MAM:\n");
			muacc_print_context(ctx);
		}

		if (-1 == _muacc_contact_mam(muacc_act_socketconnect_req, ctx))
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Got no response from MAM (Is it running?) - Failing.\n");
			return -1;
		}

		if (CLIB_IF_NOISY_DEBUG2)
		{
			printf("After MAM:\n");
			muacc_print_context(ctx);
		}

		return _muacc_socketconnect_create(ctx, s);
	}
}

int _muacc_socketconnect_create(muacc_context_t *ctx, int *s)
{
	if (ctx == NULL || s == NULL)
		return -1;

	DLOG(CLIB_IF_NOISY_DEBUG2, "Creating socket (Domain: %d, Type: %d, Protocol: %d)\n", ctx->ctx->domain, ctx->ctx->type, ctx->ctx->protocol);
	if ((*s = socket(ctx->ctx->domain, ctx->ctx->type, ctx->ctx->protocol)) != -1)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Successfully created socket %d\n", *s);
	}
	else
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	DLOG(CLIB_IF_NOISY_DEBUG2, "Setting suggested socket options\n");
	if (CLIB_IF_NOISY_DEBUG2)
	{
		printf("Socket options:\n");
		_muacc_print_socket_option_list(ctx->ctx->sockopts_suggested);
	}

	struct socketopt *so = NULL;
	for (so = ctx->ctx->sockopts_suggested; so != NULL; so = so->next)
	{
		so->returnvalue = muacc_setsockopt(ctx, *s, so->level, so->optname, so->optval, so->optlen);
		if (so->returnvalue == -1)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Setting sockopt failed: %s\n", strerror(errno));
			if (so->flags && SOCKOPT_OPTIONAL != 0)
			{
				// fail
				DLOG(CLIB_IF_NOISY_DEBUG2, "Socket option was mandatory, but failed - returning\n");
				return -1;
			}
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Socket option was set successfully\n");
			so->flags &= SOCKOPT_IS_SET;
		}

	}

	if (ctx->ctx->bind_sa_suggested != NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Attempting to bind socket %d\n", *s);
		if (CLIB_IF_NOISY_DEBUG2)
		{
			printf("Local address:\n");
			_muacc_print_socket_addr(ctx->ctx->bind_sa_suggested, ctx->ctx->bind_sa_suggested_len);
			printf("\n");
		}

		if (0 == bind(*s, ctx->ctx->bind_sa_suggested, ctx->ctx->bind_sa_suggested_len))
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Bound socket to suggested local address\n");
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Error binding to local address: %s\n", strerror(errno));
			return -1;
		}
	}

	if (ctx->ctx->remote_sa == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Got no remote address to connect to - fail\n");
		return -1;
	}
	else
	{
		if (ctx->ctx->domain == AF_INET)
			((struct sockaddr_in *) ctx->ctx->remote_sa)->sin_port = htons(ctx->ctx->remote_port);
		else if (ctx->ctx->domain == AF_INET6)
			((struct sockaddr_in6 *) ctx->ctx->remote_sa)->sin6_port = htons(ctx->ctx->remote_port);

		DLOG(CLIB_IF_NOISY_DEBUG2, "Attempting to connect the socket\n");
		if (CLIB_IF_NOISY_DEBUG2)
		{
			printf("Remote address:\n");
			_muacc_print_socket_addr(ctx->ctx->remote_sa, ctx->ctx->remote_sa_len);
			printf("\n");
		}

		if (0 != connect(*s, ctx->ctx->remote_sa, ctx->ctx->remote_sa_len))
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Connection failed: %s\n", strerror(errno));
			return -1;
		}
		else
		{
			DLOG(CLIB_IF_NOISY_DEBUG2, "Socket was successfully connected. Adding %d to list.\n", *s);

			struct socketlist *slist = _muacc_add_socket_to_list(&sockets, *s, ctx->ctx);

			if (slist != NULL)
			{
				if (CLIB_IF_NOISY_DEBUG2)
				{
					DLOG(CLIB_IF_NOISY_DEBUG2, "Socket %d was successfully added:\n", *s);
					muacc_print_socketlist(sockets);
				}
			}
			else
			{
				DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d could not be added!\n", *s);
			}
			return 1;
		}
	}
}

int _socketchoose_request(muacc_context_t *ctx, int *s, struct socketlist *slist)
{
	int ret = -1;
	ret = _muacc_send_socketchoose (ctx, s, slist);

	if (ret == 0)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Chose existing socket %d\n", *s);
		return 0;
	}
	else if (ret == 1)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "Open new socket\n");

		return _muacc_socketconnect_create(ctx, s);
	}
	return -1;
}

int socketconnect_close(int socket)
{
	DLOG(CLIB_IF_NOISY_DEBUG0, "Trying to close socket %d and remove it from list\n", socket);
	pthread_rwlock_wrlock(&socketlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Got global lock\n");
	if (_muacc_remove_socket_from_list(&sockets, socket) == -1)
	{
		DLOG(CLIB_IF_LOCKS, "LOCK: Finished trying to clean up set - Unlocking global lock\n");
		pthread_rwlock_unlock(&socketlist_lock);

		DLOG(CLIB_IF_NOISY_DEBUG1, "Could not remove socket %d from socketset list\n", socket);

		return -1;
	}
	else
	{
		DLOG(CLIB_IF_LOCKS, "LOCK: Finished trying to clean up set - Unlocking global lock\n");
		pthread_rwlock_unlock(&socketlist_lock);

		if (close(socket) == -1)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Close failed: %s\n", strerror(errno));
			return -1;
		}
		DLOG(CLIB_IF_NOISY_DEBUG0, "Successfully closed and removed socket %d\n", socket);

		return 0;
	}
}

int socketconnect_release(int socket)
{
	DLOG(CLIB_IF_NOISY_DEBUG0, "Releasing socket %d and marking it as free for reuse\n", socket);
	pthread_rwlock_wrlock(&socketlist_lock);
	DLOG(CLIB_IF_LOCKS, "LOCK: Got global lock\n");
	struct socketlist *list_to_release = _muacc_find_socketlist(sockets, socket);
	if (list_to_release == NULL || list_to_release->set == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot release it\n", socket);
		DLOG(CLIB_IF_LOCKS, "LOCK: Socket not found - Unlocking global lock\n");
		pthread_rwlock_unlock(&socketlist_lock);
		return -1;
	}
	else
	{
		struct socketset *set = list_to_release->set;
		while (set->file != socket && set != NULL)
		{
			set = set->next;
		}
		if (set == NULL)
		{
			DLOG(CLIB_IF_NOISY_DEBUG1, "Socket %d not found in list - cannot release it\n", socket);
			DLOG(CLIB_IF_LOCKS, "LOCK: Socket not found in set - Unlocking global lock\n");
			pthread_rwlock_unlock(&socketlist_lock);
			return -1;
		}
		else
		{
			set->locks = 0;
			DLOG(CLIB_IF_NOISY_DEBUG2, "Set entry of socket %d found and lock released\n", socket);
			DLOG(CLIB_IF_LOCKS, "LOCK: Released - Unlocking global lock\n");
			pthread_rwlock_unlock(&socketlist_lock);
			return 0;
		}
	}
}
