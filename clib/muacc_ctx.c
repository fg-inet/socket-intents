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


int _lock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(_ctx->locks++) );
}


int _unlock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(--(_ctx->locks)) );
}


int muacc_init_context(struct muacc_context *ctx)
{
	struct _muacc_ctx *_ctx;


	/* initalize context backing struct */
	if( ( _ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL )
	{
		perror("muacc_init_context malloc failed");
		return(-1);
	}
	memset(_ctx, 0x00, sizeof(struct _muacc_ctx));
	_ctx->usage = 1;

	/* connect to MAM */
	if(_connect_ctx_to_mam(_ctx))
	{
		/* free context backing struct */
		free(_ctx);

		/* declare interface struct invalid */
		ctx->ctx = NULL;
		return(-1);
	}

	DLOG(CLIB_CTX_NOISY_DEBUG,"connected & context successfully initalized\n");

	ctx->ctx = _ctx;
	return(0);
}

int muacc_retain_context(struct muacc_context *ctx)
{
	if(ctx->ctx == 0)
	{
		return(-1);
	}

	return(++(ctx->ctx->usage));
}

int muacc_release_context(struct muacc_context *ctx)
{
	if(ctx == NULL)
	{
		DLOG(CLIB_CTX_NOISY_DEBUG, "WARNING: tried to release NULL POINTER context\n");		
		return -1;
	}
	else if(ctx->ctx == NULL)
	{
		DLOG(CLIB_CTX_NOISY_DEBUG, "empty context - nothing to release\n");
		return 0;
	}		
	else if( --(ctx->ctx->usage) == 0 )
	{
		DLOG(CLIB_CTX_NOISY_DEBUG, "trying to free data fields\n");		
		
		close(ctx->ctx->mamsock);
		if (ctx->ctx->remote_addrinfo_hint != NULL) freeaddrinfo(ctx->ctx->remote_addrinfo_hint);
		if (ctx->ctx->remote_addrinfo_res != NULL) freeaddrinfo(ctx->ctx->remote_addrinfo_res);
		if (ctx->ctx->bind_sa_req != NULL) free(ctx->ctx->bind_sa_req);
		if (ctx->ctx->bind_sa_res != NULL) free(ctx->ctx->bind_sa_res);
		if (ctx->ctx->remote_sa_req != NULL) free(ctx->ctx->remote_sa_req);
		if (ctx->ctx->remote_sa_res != NULL) free(ctx->ctx->remote_sa_res);
		if (ctx->ctx->remote_hostname != NULL) free(ctx->ctx->remote_hostname);
		while (ctx->ctx->socket_options != NULL)
		{
			socketopt_t *current = ctx->ctx->socket_options;
			ctx->ctx->socket_options = current->next;
			free(current);
		}
		free(ctx->ctx);
	}
	
	DLOG(CLIB_CTX_NOISY_DEBUG, "context successfully freed\n");
	
	return(ctx->ctx->usage);
}








int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src) 
{
	struct _muacc_ctx *_ctx;
	
	if(src->ctx == NULL)
	{
		DLOG(CLIB_CTX_NOISY_DEBUG,"warning: cloning uninitalized context\n");
		dst->ctx = NULL;
		return(0);
	}
	
	if( (_ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL ) 
	{
		perror("muacc_clone_context malloc failed");
		return(-1);	
	}
	
	memcpy(_ctx, src->ctx, sizeof(struct _muacc_ctx));
	
	_ctx->bind_sa_req   = _muacc_clone_sockaddr(src->ctx->bind_sa_req, src->ctx->bind_sa_req_len);      
	_ctx->bind_sa_res   = _muacc_clone_sockaddr(src->ctx->bind_sa_res, src->ctx->bind_sa_res_len);      
	_ctx->remote_sa_req = _muacc_clone_sockaddr(src->ctx->remote_sa_req, src->ctx->remote_sa_req_len);    
	_ctx->remote_sa_res = _muacc_clone_sockaddr(src->ctx->remote_sa_res, src->ctx->remote_sa_res_len);    
	
	_ctx->remote_addrinfo_hint = _muacc_clone_addrinfo(src->ctx->remote_addrinfo_hint);	
	_ctx->remote_addrinfo_res  = _muacc_clone_addrinfo(src->ctx->remote_addrinfo_res);	
	
	_ctx->remote_hostname = _muacc_clone_string(src->ctx->remote_hostname);
	
	_ctx->socket_options = _muacc_clone_socketopts(src->ctx->socket_options);

	_ctx->usage = 1;
	dst->ctx = _ctx;
	
	/* connect to MAM */
	if(_connect_ctx_to_mam(_ctx))
	{
		/* free context backing struct */
		muacc_release_context(dst);
	
		/* declare interface struct invalid */
		dst->ctx = NULL;
		return(-1);	
	}
	
	return(0);	
}


size_t _muacc_pack_ctx(char *buf, size_t *pos, size_t len, const struct _muacc_ctx *ctx)
{

	size_t pos0 = *pos;

	DLOG(CLIB_CTX_NOISY_DEBUG,"bind_sa_req pos=%ld\n", (long) *pos);
    if( ctx->bind_sa_req != NULL &&
    	0 > _muacc_push_tlv(buf, pos, len, bind_sa_req,		ctx->bind_sa_req, 		ctx->bind_sa_req_len        ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG,"bind_sa_res pos=%ld\n", (long) *pos);
	if( ctx->bind_sa_res != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, bind_sa_res,		ctx->bind_sa_res,		ctx->bind_sa_res_len        ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG,"remote_sa_req pos=%ld\n", (long) *pos);
	if( ctx->remote_sa_req != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, remote_sa_req,  	ctx->remote_sa_req, 	ctx->remote_sa_req_len      ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG,"remote_sa_res pos=%ld\n", (long) *pos);
	if( ctx->remote_sa_res != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, remote_sa_res,  	ctx->remote_sa_res, 	ctx->remote_sa_res_len      ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG,"remote_hostname pos=%ld\n", (long) *pos);
	if( ctx->remote_hostname != NULL && /* strlen(NULL) might have undesired side effects… */
		0 > _muacc_push_tlv(buf, pos, len, remote_hostname,	ctx->remote_hostname, strlen(ctx->remote_hostname)) ) goto _muacc_pack_ctx_err;
    
	DLOG(CLIB_CTX_NOISY_DEBUG,"remote_addrinfo_hint pos=%ld\n", (long) *pos);
	if( 0 > _muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_hint, ctx->remote_addrinfo_hint) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG,"remote_addrinfo_res pos=%ld\n", (long) *pos);
	if( 0 > _muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_res,  ctx->remote_addrinfo_res ) ) goto _muacc_pack_ctx_err;

	return ( *pos - pos0 );
	
_muacc_pack_ctx_err:

	return(-1);
	
}


int _muacc_unpack_ctx(muacc_tlv_t tag, const void *data, size_t data_len, struct _muacc_ctx *_ctx)
{
	struct addrinfo *ai;
	struct sockaddr *sa;
	char *str;


	switch(tag) 
	{
		case bind_sa_req:
			DLOG(CLIB_CTX_NOISY_DEBUG, "unpacking bind_sa_req\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_req);
				_ctx->bind_sa_req = sa;
			}
			else
				return(-1);
			break;
		case bind_sa_res:
			DLOG(CLIB_CTX_NOISY_DEBUG, "unpacking bind_sa_res\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_res);
				_ctx->bind_sa_res = sa;
			}
			else
				return(-1);
			break;
		case remote_sa_req:
			DLOG(CLIB_CTX_NOISY_DEBUG, "unpacking remote_sa_req\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->remote_sa_req);
				_ctx->remote_sa_req = sa;
			}
			else
				return(-1);
			break;
		case remote_sa_res:
			DLOG(CLIB_CTX_NOISY_DEBUG, "unpacking remote_sa_res\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->remote_sa_res);
				_ctx->remote_sa_res = sa;
			}
			else
				return(-1);
			break;
		case remote_hostname:
			DLOG(CLIB_CTX_NOISY_DEBUG, "unpacking remote_hostname\n");
			if((str = malloc(data_len)) != NULL)
			{
				str[data_len-1] = 0x00;
				_ctx->remote_hostname = str;
			}
			else
				return -1;
			break;
		case remote_addrinfo_hint:
			DLOG(CLIB_CTX_NOISY_DEBUG, "unpacking remote_addrinfo_hint\n");
			if( _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_hint);
				_ctx->remote_addrinfo_hint = ai;
			}
			else
				return(-1);
			break;

		case remote_addrinfo_res:
			DLOG(CLIB_CTX_NOISY_DEBUG, "unpacking remote_addrinfo_res\n");
			if( _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_res);
				_ctx->remote_addrinfo_res = ai;
			}
			else
				return(-1);
			break;

		default:
			DLOG(CLIB_CTX_NOISY_DEBUG, "_muacc_unpack_ctx: ignoring unknown tag %x\n", tag);
			break;
	}

	return(0);

} 


void muacc_print_context(struct muacc_context *ctx)
{
	if (ctx == NULL)
	{
		printf("ctx = NULL\n");
	}
	if (ctx->ctx == NULL)
	{
		printf("ctx->ctx = NULL\n");
	}
	else
	{
		printf("ctx->ctx = {\n");
		printf("\t// internal values\n");
		printf("\tusage = %d\n", ctx->ctx->usage);
		printf("\tlocks = %d\n", (int) ctx->ctx->locks);
		printf("\tmamsock = %d\n", ctx->ctx->mamsock);
		printf("\tbuf = %p\n", ctx->ctx->buf);

		printf("\t// exported values\n");
		printf("\tbind_sa_req = ");
		_muacc_print_sockaddr(ctx->ctx->bind_sa_req, ctx->ctx->bind_sa_req_len);
		printf("\n");
		printf("\tbind_sa_res = ");
		_muacc_print_sockaddr(ctx->ctx->bind_sa_res, ctx->ctx->bind_sa_res_len);
		printf("\n");
		printf("\tremote_sa_req = ");
		_muacc_print_sockaddr(ctx->ctx->remote_sa_req, ctx->ctx->remote_sa_req_len);
		printf("\n");
		printf("\tremote_hostname = %s\n", ctx->ctx->remote_hostname);
		printf("\tremote_addrinfo_hint = ");
		_muacc_print_addrinfo(ctx->ctx->remote_addrinfo_hint);
		printf("\n");
		printf("\tremote_addrinfo_res = ");
		_muacc_print_addrinfo(ctx->ctx->remote_addrinfo_res);
		printf("\n");
		printf("\tremote_sa_res = ");
		_muacc_print_sockaddr(ctx->ctx->remote_sa_res, ctx->ctx->remote_sa_res_len);
		printf("\n");
		printf("\tsocket_options = ");
		_muacc_print_socket_options(ctx->ctx->socket_options);
		printf("\n");
	}
}
