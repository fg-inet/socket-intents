#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "../config.h"

#include "muacc.h"
#include "muacc_ctx.h"
#include "muacc_tlv.h"
#include "muacc_util.h"
#include "dlog.h"

#ifdef USE_SO_INTENTS
#include "../libintents/libintents.h"
#endif


int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res)		
{
	
	int ret;
	
	if(ctx->ctx == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context uninialized - fallback to regual connect\n");
		goto muacc_getaddrinfo_fallback;
	}

	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context already in use - fallback to regual connect\n");
		_unlock_ctx(ctx->ctx);
		goto muacc_getaddrinfo_fallback;
	}

	/* save hostname */
	if(ctx->ctx->remote_hostname != NULL)
		free(ctx->ctx->remote_hostname);
	ctx->ctx->remote_hostname = _muacc_clone_string(hostname);
	
	/* save hint */
	if(ctx->ctx->remote_addrinfo_hint != NULL)
		freeaddrinfo(ctx->ctx->remote_addrinfo_hint);
	ctx->ctx->remote_addrinfo_hint = _muacc_clone_addrinfo(hints);
	
	/* contact mam */
	_muacc_contact_mam(muacc_act_getaddrinfo_preresolve_req, ctx->ctx);
	
	if(ctx->ctx->remote_addrinfo_res != NULL)
		ret = 0;
	else
	{
		
		/* do query on our own */
		ret = 	 getaddrinfo(hostname, servname, hints, res);	
		if (ret == 0)
		{
			/* save response */
			ctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(*res);

			/* contact mam again */
			_muacc_contact_mam(muacc_act_getaddrinfo_postresolve_req, ctx->ctx);
		}
	}

	_unlock_ctx(ctx->ctx);
	
	return ret;
	
muacc_getaddrinfo_fallback:

	return getaddrinfo(hostname, servname, hints, res);	
		
}


int muacc_setsockopt(struct muacc_context *ctx, int socket, int level, int option_name,
    const void *option_value, socklen_t option_len)
{	
	int retval = -2; // Return value; will be set, else structure problem in function

	if( ctx->ctx == 0 )
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context uninialized - fallback to regual setsockopt\n");
		return setsockopt(socket, level, option_name, option_value, option_len);
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context already in use - fallback to regual setsockopt\n");
		_unlock_ctx(ctx->ctx);
		return setsockopt(socket, level, option_name, option_value, option_len);
	}
	
	#ifdef USE_SO_INTENTS
	if (level == SOL_INTENTS)
	{
		// Intent socket options are handled by us
		if (option_value == NULL || option_len == NULL)
		{
			// Invalid buffer
			errno = EFAULT;
			_unlock_ctx(ctx->ctx);
			return -1;
		}
	}
	else
	#endif
	{
		// Socket option not an intent: Call original setsockopt function
		if ((retval = setsockopt(socket, level, option_name, option_value, option_len)) < 0)
		{
			_unlock_ctx(ctx->ctx);
			return retval;
		}
		
		retval = 0;
	}
	
	/* we have set sucsessfully an socket option or checked an intend - save for MAM */
	
	/* Create a new socketopt entry for the socket option list */
	struct socketopt *newopt = malloc(sizeof(struct socketopt));
	newopt->level = level;
	newopt->optname = option_name;
	newopt->optlen = option_len;
	newopt->optval = malloc(option_len);
	if (newopt->optval == NULL)
	{
		perror("__function__ malloc failed");
		_unlock_ctx(ctx->ctx);
		return retval;
	}
	memcpy(newopt->optval, option_value, option_len);
	newopt->next = NULL;

	/* put it in the context */
	if (ctx->ctx->socket_options == NULL)
	{
		/* Add first socket option to the empty list */
		ctx->ctx->socket_options = newopt;
	}
	else
	{
		/* Search for last socket option of the current list */
		struct socketopt *current = ctx->ctx->socket_options;
		while (current->next != NULL)
			current = current->next;
		/* Add new option to the end of the socket_option list */
		current->next = newopt;
	}

	_unlock_ctx(ctx->ctx);

	return retval;
}

int muacc_getsockopt(struct muacc_context *ctx, int socket, int level, int option_name,
    void *option_value, socklen_t *option_len)
{
	int retval = -2; // Return value, will be set, else structure problem in function

	if( ctx->ctx == 0 )
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context uninialized - fallback to regual getsockopt\n");
		return getsockopt(socket, level, option_name, option_value, option_len);
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context already in use - fallback to regual getsockopt\n");
		_unlock_ctx(ctx->ctx);
		return getsockopt(socket, level, option_name, option_value, option_len);
	}


	#ifdef USE_SO_INTENTS
	if( level == SOL_INTENTS)
	{
		// Intent socket options are handled by us
		if (option_value == NULL || option_len == NULL)
		{
			// Invalid buffer
			errno = EFAULT;
			_unlock_ctx(ctx->ctx);
			return -1;
		}
		struct socketopt *current = ctx->ctx->socket_options;
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
	#endif
	{
		// Requested socket option is not on 'intents' layer
		if ((retval = getsockopt(socket, level, option_name, option_value, option_len)) < 0)
		{
			_unlock_ctx(ctx->ctx);
			return retval;
		}
	}

	// If we arrive here, we have successfully gotten the option (intent or other)

	_unlock_ctx(ctx->ctx);

	return retval;
}

int muacc_connect(struct muacc_context *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len)
{	
	DLOG(CLIB_IF_NOISY_DEBUG, "invoked\n");
	
	if( ctx->ctx == 0 )
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context uninialized - fallback to regual connect\n");
		goto muacc_connect_fallback;
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG, "context already in use - fallback to regual connect\n");
		_unlock_ctx(ctx->ctx);
		goto muacc_connect_fallback;
	}
	
	ctx->ctx->remote_sa_req     = _muacc_clone_sockaddr((struct sockaddr *)address, address_len);
	ctx->ctx->remote_sa_req_len = address_len;
	
	if(ctx->ctx->remote_sa_res == NULL)
	{
		/* set default request as default */
		ctx->ctx->remote_sa_res 	= _muacc_clone_sockaddr((struct sockaddr *)address, address_len);
		ctx->ctx->remote_sa_res_len	= address_len;
	}
	
	if( _muacc_contact_mam(muacc_act_connect_req, ctx->ctx) <0 ){
		_unlock_ctx(ctx->ctx);
		DLOG(CLIB_IF_NOISY_DEBUG, "got no response from mam - fallback to regual connect\n");
		goto muacc_connect_fallback;
	}
	
	_unlock_ctx(ctx->ctx);
	
	return connect(socket, ctx->ctx->remote_sa_res, ctx->ctx->remote_sa_res_len);
	
	
muacc_connect_fallback:
	
	return connect(socket, address, address_len);
		
}			
