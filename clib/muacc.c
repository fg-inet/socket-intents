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
#include "../libintents/libintents.h"

#ifdef USE_SO_INTENTS
#include "../libintents/libintents.h"
#endif

#define CLIB_IF_NOISY_DEBUG0 1
#define CLIB_IF_NOISY_DEBUG1 0
#define CLIB_IF_NOISY_DEBUG2 0



int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res)
{
	
	int ret;
	
	if(ctx->ctx == NULL)
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - fallback to regular connect\n");
		goto muacc_getaddrinfo_fallback;
	}

	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular connect\n");
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
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - fallback to regular setsockopt\n");
		return setsockopt(socket, level, option_name, option_value, option_len);
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular setsockopt\n");
		_unlock_ctx(ctx->ctx);
		return setsockopt(socket, level, option_name, option_value, option_len);
	}
	
	#ifdef USE_SO_INTENTS
	if (level == SOL_INTENTS)
	{
		// Intent socket options are handled by us
		if (option_value == NULL)
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

	/* we have set successfully an socket option or checked an intend - save for MAM */

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
	DLOG(CLIB_IF_NOISY_DEBUG2, "Added new option to the end of the list:\n\t\t\t");
	if (CLIB_IF_NOISY_DEBUG2) _muacc_print_socket_option_list(newopt);

	retval = 0;

	_unlock_ctx(ctx->ctx);

	return retval;
}

int muacc_getsockopt(struct muacc_context *ctx, int socket, int level, int option_name,
    void *option_value, socklen_t *option_len)
{
	int retval = -2; // Return value, will be set, else structure problem in function

	if( ctx->ctx == 0 )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - fallback to regular getsockopt\n");
		return getsockopt(socket, level, option_name, option_value, option_len);
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular getsockopt\n");
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

		DLOG(CLIB_IF_NOISY_DEBUG2, "Looking for socket option: \n\t\t\t{ { level = %d, optname = %d } }\n", level, option_name, (int *) option_value);

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
	DLOG(CLIB_IF_NOISY_DEBUG2, "invoked\n");
	
	if( ctx->ctx == 0 )
	{
		DLOG(CLIB_IF_NOISY_DEBUG1, "context uninitialized - fallback to regular connect\n");
		goto muacc_connect_fallback;
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_IF_NOISY_DEBUG0, "WARNING: context already in use - fallback to regular connect\n");
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
		DLOG(CLIB_IF_NOISY_DEBUG0, "got no response from mam - fallback to regular connect\n");
		goto muacc_connect_fallback;
	}
	
	_unlock_ctx(ctx->ctx);
	
	return connect(socket, ctx->ctx->remote_sa_res, ctx->ctx->remote_sa_res_len);
	
	
muacc_connect_fallback:
	
	return connect(socket, address, address_len);
		
}			

#ifdef _TEST_MUACC_LIB
int main(int argc, char *argv[])
{

	struct muacc_context testctx = { .ctx = NULL };

	if (muacc_init_context(&testctx) < 0)
	{
		printf("Error initializing muacc_ctx\n");
	}
	else
	{
		struct in_addr v4addr = { .s_addr = 0};
		inet_aton("8.8.8.8", &v4addr);
		struct sockaddr_in v4sockaddr = { .sin_family = AF_INET, .sin_port = htons(2342), .sin_addr = v4addr};
		testctx.ctx->bind_sa_req = (struct sockaddr *) &v4sockaddr;

	/*	struct addrinfo testaddrinfo = { .ai_flags = 0, .ai_family = AF_INET, .ai_socktype = 1, .ai_protocol = 8, .ai_addr = (struct sockaddr *) &v4sockaddr, .ai_canonname = "maunz.org" };

		testctx.ctx->remote_addrinfo_hint = &testaddrinfo;
		*/
		struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_flags = AI_PASSIVE };
		struct addrinfo *result;

		if (getaddrinfo("www.google.com", NULL, &hints, &result) != 0)
		{
			printf("Getaddrinfo failed: %s \n", gai_strerror(errno));
		}
		else
		{
			testctx.ctx->remote_addrinfo_hint = &hints;
			testctx.ctx->remote_addrinfo_res = result;
		}

		struct socketopt testopt = { .level = SOL_SOCKET, .optname = SO_BROADCAST, .optval=malloc(sizeof(int)), .optlen = sizeof(int) };
		int flag = 1;
		testopt.optval = &flag;

		struct socketopt testopt2 = { .level = SOL_INTENTS, .optname = SO_CATEGORY, .optval=malloc(sizeof(enum category)), .optlen = sizeof(enum category) };
		enum category cat = C_KEEPALIVES;
		testopt2.optval = &cat;
		testopt.next = &testopt2;

		testctx.ctx->socket_options = &testopt;

		muacc_print_context(&testctx);

		struct socketopt *newopt;

		newopt = _muacc_clone_socketopts((const struct socketopt *) &testopt);

		if (newopt != NULL)
		{
			printf("Cloned socketopts.\n");
		}
	}

}
#endif
