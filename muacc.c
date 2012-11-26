#include "muacc.h"
#include <stdlib.h>
#include <string.h>

int muacc_init_context(struct muacc_context *ctx)
{
	struct _muacc_ctx *_ctx;
	
	if( ( _ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL )
	{
		return(-1);	
	}
	memset(_ctx, 0x00, sizeof(struct _muacc_ctx));
	
	_ctx->usage = 1;
	ctx->ctx = _ctx;
	
	return(0);	
}

int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src) 
{
	struct _muacc_ctx *_ctx;
	
	if( (_ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL ) 
	{
		return(-1);	
	}
	
	memcpy(_ctx, src->ctx, sizeof(struct _muacc_ctx));
	
	_ctx->usage = 1;
	dst->ctx = _ctx;
	
	return(0);	
}

int muacc_release_context(struct muacc_context *ctx)
{
	if( (ctx->ctx->usage--) == 0 )
	{
		free(ctx->ctx);
	}
	ctx->ctx = NULL;
	
	return(ctx->ctx->usage);
}

int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res)		
{
	return getaddrinfo(hostname, servname, hints, res);	
}


int muacc_setsockopt(struct muacc_context *ctx, int socket, int level, int option_name,
    const void *option_value, socklen_t option_len);

int muacc_connect(struct muacc_context *ctx,
	    int socket, struct sockaddr *address, socklen_t address_len)
{
	return connect(socket, address, address_len);
}			