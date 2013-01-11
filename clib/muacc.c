#include "muacc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include "../config.h"


int muacc_init_context(struct muacc_context *ctx)
{
	struct _muacc_ctx *_ctx;
	
	struct sockaddr_un mams;
	mams.sun_len = sizeof(struct sockaddr_un);
	mams.sun_family = AF_UNIX;
	strncpy( mams.sun_path, MUACC_SOCKET, sizeof(mams.sun_path));
	
	/* initalize context backing struct */
	if( ( _ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL )
	{
		perror("muacc_init_context malloc failed");
		return(-1);
	}
	memset(_ctx, 0x00, sizeof(struct _muacc_ctx));	
	_ctx->usage = 1;
	
	/* connect to mam */
	if(_ctx->msock = socket(PF_UNIX, SOCK_STREAM, 0) < 1)
	{
		perror("muacc_init_context socket creation failed");
		goto muacc_init_context_err;	
	}
	if(connect(_ctx->msock, (struct sockaddr*) &mams, sizeof(mams)) < 0)
	{
		fprintf(stderr, "muacc_init_context connect to mam via %s failed: %s\n", mams.sun_path, strerror(errno));
		goto muacc_init_context_err;
	}
	
	ctx->ctx = _ctx;
	return(0);

muacc_init_context_err:
	
	/* free context backing struct */
	free(_ctx);
	
	/* declare interface struct invalid */
	ctx->ctx = NULL;
	return(-2);	
}

int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src) 
{
	struct _muacc_ctx *_ctx;
	
	if(src->ctx == NULL)
	{
		dst->ctx = NULL;
		return(0);
	}
	
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
	if(ctx->ctx == 0)
	{
		return(-1);
	}
		
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
	if(ctx->ctx == 0)
	{
		return getaddrinfo(hostname, servname, hints, res);	
	}
	
}


int muacc_setsockopt(struct muacc_context *ctx, int socket, int level, int option_name,
    const void *option_value, socklen_t option_len);

int muacc_connect(struct muacc_context *ctx,
	    int socket, struct sockaddr *address, socklen_t address_len)
{
	if(ctx->ctx == 0)
	{
		return connect(socket, address, address_len);
	}
	
}			