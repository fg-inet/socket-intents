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

#ifndef CLIB_CTX_NOISY_DEBUG0
#define CLIB_CTX_NOISY_DEBUG0 1
#endif

#ifndef CLIB_CTX_NOISY_DEBUG1
#define CLIB_CTX_NOISY_DEBUG1 0
#endif

#ifndef CLIB_CTX_NOISY_DEBUG2
#define CLIB_CTX_NOISY_DEBUG2 0
#endif


int _lock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(_ctx->locks++) );
}


int _unlock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(--(_ctx->locks)) );
}

struct _muacc_ctx *_muacc_create_ctx()
{

	struct _muacc_ctx *_ctx;


	/* initalize context backing struct */
	if( ( _ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL )
	{
		perror("_muacc_ctx malloc failed");
		return(NULL);
	}
	memset(_ctx, 0x00, sizeof(struct _muacc_ctx));
	_ctx->usage = 1;

	DLOG(CLIB_CTX_NOISY_DEBUG1,"created new _ctx=%p successfully  \n", (void *) _ctx);

	return _ctx;
}

int muacc_init_context(struct muacc_context *ctx)
{
	struct _muacc_ctx *_ctx = _muacc_create_ctx();

	if(_ctx == NULL)
		return(-1);

	/* connect to MAM */
	if(_muacc_connect_ctx_to_mam(_ctx))
	{
		DLOG(CLIB_CTX_NOISY_DEBUG0,"warning: could not connect to MAM\n");

		/* free context backing struct */
		free(_ctx);

		/* declare interface struct invalid */
		ctx->ctx = NULL;
		return(-1);
	}

	DLOG(CLIB_CTX_NOISY_DEBUG1,"connected & context successfully initalized\n");

	ctx->ctx = _ctx;
	return(0);
}

int _muacc_retain_ctx(struct _muacc_ctx *_ctx)
{
	return(++(_ctx->usage));
}


int muacc_retain_context(struct muacc_context *ctx)
{
	if(ctx->ctx == NULL)
	{
		return(-1);
	}

	return(_muacc_retain_ctx(ctx->ctx));
}


int _muacc_free_ctx (struct _muacc_ctx *_ctx)
{
	if( --(_ctx->usage) == 0 )
	{
		DLOG(CLIB_CTX_NOISY_DEBUG2, "trying to free data fields\n");
		
		if (_ctx->mamsock != 0) 				close(_ctx->mamsock);
		if (_ctx->remote_addrinfo_hint != NULL) freeaddrinfo(_ctx->remote_addrinfo_hint);
		if (_ctx->remote_addrinfo_res != NULL)  freeaddrinfo(_ctx->remote_addrinfo_res);
		if (_ctx->bind_sa_req != NULL)          free(_ctx->bind_sa_req);
		if (_ctx->bind_sa_res != NULL)          free(_ctx->bind_sa_res);
		if (_ctx->remote_sa_req != NULL)        free(_ctx->remote_sa_req);
		if (_ctx->remote_sa_res != NULL)        free(_ctx->remote_sa_res);
		if (_ctx->remote_hostname != NULL)      free(_ctx->remote_hostname);
		while (_ctx->socket_options != NULL)
		{
			socketopt_t *current = _ctx->socket_options;
			_ctx->socket_options = current->next;
			free(current);
		}
		free(_ctx);
		DLOG(CLIB_CTX_NOISY_DEBUG1, "context successfully freed\n");

		return(0);
	} else {
		DLOG(CLIB_CTX_NOISY_DEBUG1, "context has still %d references\n", _ctx->usage);
		return(_ctx->usage);
	}
}


int muacc_release_context(struct muacc_context *ctx)
{
	if(ctx == NULL)
	{
		DLOG(CLIB_CTX_NOISY_DEBUG0, "WARNING: tried to release NULL POINTER context\n");
		return -1;
	}
	else if(ctx->ctx == NULL)
	{
		DLOG(CLIB_CTX_NOISY_DEBUG1, "empty context - nothing to release\n");
		return 0;
	}
	else
	{
		return _muacc_free_ctx(ctx->ctx);
	}
}


int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src) 
{
	struct _muacc_ctx *_ctx;
	
	if(src->ctx == NULL)
	{
		DLOG(CLIB_CTX_NOISY_DEBUG0,"WARNING: cloning uninitalized context\n");
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
	if(_muacc_connect_ctx_to_mam(_ctx))
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

	DLOG(CLIB_CTX_NOISY_DEBUG1,"packing _ctx=%p pos=%ld\n", (void *) ctx, (long) *pos);

	DLOG(CLIB_CTX_NOISY_DEBUG2,"bind_sa_req pos=%ld\n", (long) *pos);
    if( ctx->bind_sa_req != NULL &&
    	0 > _muacc_push_tlv(buf, pos, len, bind_sa_req,		ctx->bind_sa_req, 		ctx->bind_sa_req_len        ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"bind_sa_res pos=%ld\n", (long) *pos);
	if( ctx->bind_sa_res != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, bind_sa_res,		ctx->bind_sa_res,		ctx->bind_sa_res_len        ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_sa_req pos=%ld\n", (long) *pos);
	if( ctx->remote_sa_req != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, remote_sa_req,  	ctx->remote_sa_req, 	ctx->remote_sa_req_len      ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_sa_res pos=%ld\n", (long) *pos);
	if( ctx->remote_sa_res != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, remote_sa_res,  	ctx->remote_sa_res, 	ctx->remote_sa_res_len      ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_hostname pos=%ld\n", (long) *pos);
	if( ctx->remote_hostname != NULL && /* strlen(NULL) might have undesired side effects… */
		0 > _muacc_push_tlv(buf, pos, len, remote_hostname,	ctx->remote_hostname, strlen(ctx->remote_hostname)) ) goto _muacc_pack_ctx_err;
    
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_addrinfo_hint pos=%ld\n", (long) *pos);
	if( 0 > _muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_hint, ctx->remote_addrinfo_hint) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_addrinfo_res pos=%ld\n", (long) *pos);
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
		case action:
				DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking action\n");
				_ctx->state = *((muacc_mam_action_t *) data);
				break;
		case bind_sa_req:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking bind_sa_req\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_req);
				_ctx->bind_sa_req = sa;
			}
			else
				return(-1);
			break;
		case bind_sa_res:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking bind_sa_res\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_res);
				_ctx->bind_sa_res = sa;
			}
			else
				return(-1);
			break;
		case remote_sa_req:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_sa_req\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->remote_sa_req);
				_ctx->remote_sa_req = sa;
			}
			else
				return(-1);
			break;
		case remote_sa_res:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_sa_res\n");
			if( _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->remote_sa_res);
				_ctx->remote_sa_res = sa;
			}
			else
				return(-1);
			break;
		case remote_hostname:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_hostname\n");
			if((str = malloc(data_len)) != NULL)
			{
				str[data_len-1] = 0x00;
				_ctx->remote_hostname = str;
			}
			else
				return -1;
			break;
		case remote_addrinfo_hint:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_addrinfo_hint\n");
			if( _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_hint);
				_ctx->remote_addrinfo_hint = ai;
			}
			else
				return(-1);
			break;

		case remote_addrinfo_res:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_addrinfo_res\n");
			if( _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_res);
				_ctx->remote_addrinfo_res = ai;
			}
			else
				return(-1);
			break;

		default:
			DLOG(CLIB_CTX_NOISY_DEBUG0, "_muacc_unpack_ctx: ignoring unknown tag %x\n", tag);
			break;
	}

	return(0);

} 


void muacc_print_context(struct muacc_context *ctx)
{
	char buf[4096] = {0};
	size_t buf_len = 4096;
	size_t buf_pos = 0;

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
		_muacc_print_ctx(buf, &buf_pos, buf_len, ctx->ctx);
		printf("/**************************************/\n%s\n/**************************************/\n", buf);
	}
}

void _muacc_print_ctx(char *buf, size_t *buf_pos, size_t buf_len, const struct _muacc_ctx *_ctx)
{


		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "_ctx = {\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\t// internal values\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tusage = %d,\n", _ctx->usage);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tlocks = %d,\n", (int) _ctx->locks);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tmamsock = %d,\n", _ctx->mamsock);

		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\t// exported values\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tbind_sa_req = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, _ctx->bind_sa_req, _ctx->bind_sa_req_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tbind_sa_res = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, _ctx->bind_sa_res, _ctx->bind_sa_res_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_sa_req = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, _ctx->remote_sa_req, _ctx->remote_sa_req_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_hostname = %s,\n", _ctx->remote_hostname);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_addrinfo_hint = ");
		_muacc_print_addrinfo(buf, buf_pos, buf_len, _ctx->remote_addrinfo_hint);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_addrinfo_res = ");
		_muacc_print_addrinfo(buf, buf_pos, buf_len, _ctx->remote_addrinfo_res);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_sa_res = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, _ctx->remote_sa_res, _ctx->remote_sa_res_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tsocket_options = ");
		_muacc_print_socket_options(buf, buf_pos, buf_len, _ctx->socket_options);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\n}\n");

}
