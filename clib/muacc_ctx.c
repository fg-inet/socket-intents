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


int _lock_ctx (muacc_context_t *ctx)
{
	return( -(ctx->locks++) );
}


int _unlock_ctx (muacc_context_t *ctx)
{
	return( -(--(ctx->locks)) );
}

muacc_ctxid_t _get_ctxid()
{
    static uint32_t cnt = 0;
	return ( ((uint64_t) (cnt++)) + (((uint64_t) getpid()) << 32) );
}

struct _muacc_ctx *_muacc_create_ctx()
{

	struct _muacc_ctx *_ctx;

	/* initialize context backing struct */
	if( ( _ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL )
	{
		perror("_muacc_ctx malloc failed");
		return(NULL);
	}
	memset(_ctx, 0x00, sizeof(struct _muacc_ctx));
	_ctx->ctxid = -1;

	DLOG(CLIB_CTX_NOISY_DEBUG1,"created new _ctx=%p successfully  \n", (void *) _ctx);

	return _ctx;
}

int muacc_init_context(struct muacc_context *ctx)
{
	struct _muacc_ctx *_ctx = _muacc_create_ctx();

	if(_ctx == NULL || ctx == NULL)
		return(-1);
	_ctx->ctxid = _get_ctxid(); 

	DLOG(CLIB_CTX_NOISY_DEBUG1,"context successfully initialized\n");

	ctx->usage = 1;
	ctx->locks = 0;
	ctx->mamsock = -1;

	ctx->ctx = _ctx;
	return(0);
}


int muacc_retain_context(struct muacc_context *ctx)
{
	if(ctx->ctx == NULL)
	{
		return(-1);
	}

	return(++(ctx->usage));
}


int _muacc_free_ctx (struct _muacc_ctx *_ctx)
{
	DLOG(CLIB_CTX_NOISY_DEBUG2, "trying to free data fields\n");

	if (_ctx->remote_addrinfo_hint != NULL) freeaddrinfo(_ctx->remote_addrinfo_hint);
	if (_ctx->remote_addrinfo_res != NULL)  freeaddrinfo(_ctx->remote_addrinfo_res);
	if (_ctx->bind_sa_req != NULL)          free(_ctx->bind_sa_req);
	if (_ctx->bind_sa_suggested != NULL)          free(_ctx->bind_sa_suggested);
	if (_ctx->remote_sa != NULL)        free(_ctx->remote_sa);
	if (_ctx->remote_hostname != NULL)      free(_ctx->remote_hostname);
	while (_ctx->sockopts_current != NULL)
	{
		socketopt_t *current = _ctx->sockopts_current;
		_ctx->sockopts_current = current->next;
		free(current);
	}
	while (_ctx->sockopts_suggested != NULL)
	{
		socketopt_t *current = _ctx->sockopts_suggested;
		_ctx->sockopts_suggested = current->next;
		free(current);
	}
	free(_ctx);
	DLOG(CLIB_CTX_NOISY_DEBUG1, "context successfully freed\n");

	return(0);
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
		if( --(ctx->usage) == 0 )
		{
			if (ctx->mamsock != -1) 				close(ctx->mamsock);
			return _muacc_free_ctx(ctx->ctx);
		} else {
			DLOG(CLIB_CTX_NOISY_DEBUG1, "context has still %d references\n", ctx->usage);
			return(ctx->usage);
		}
	}
}


int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src) 
{
	struct _muacc_ctx *_ctx;
	
	if(src->ctx == NULL)
	{
		DLOG(CLIB_CTX_NOISY_DEBUG0,"WARNING: cloning uninitialized context\n");
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
	_ctx->bind_sa_suggested   = _muacc_clone_sockaddr(src->ctx->bind_sa_suggested, src->ctx->bind_sa_suggested_len);      
	
	_ctx->remote_addrinfo_hint = _muacc_clone_addrinfo(src->ctx->remote_addrinfo_hint);	
	_ctx->remote_addrinfo_res  = _muacc_clone_addrinfo(src->ctx->remote_addrinfo_res);	
	
	_ctx->remote_hostname = _muacc_clone_string(src->ctx->remote_hostname);
	
	_ctx->sockopts_current = _muacc_clone_socketopts(src->ctx->sockopts_current);
	_ctx->sockopts_suggested = _muacc_clone_socketopts(src->ctx->sockopts_suggested);

	_ctx->ctxid = _get_ctxid();
	
	dst->usage = 1;
	dst->locks = 0;
	dst->mamsock = -1;
	dst->ctx = _ctx;
	
	
	
	return(0);	
}


size_t _muacc_pack_ctx(char *buf, size_t *pos, size_t len, const struct _muacc_ctx *ctx)
{

	size_t pos0 = *pos;

	DLOG(CLIB_CTX_NOISY_DEBUG1,"packing _ctx=%p pos=%zd\n", (void *) ctx, *pos);

	DLOG(CLIB_CTX_NOISY_DEBUG2,"ctxid pos=%ld\n", (long) *pos);
    if(	0 > _muacc_push_tlv(buf, pos, len, ctxid, &(ctx->ctxid), sizeof(ctx->ctxid) ) ) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"calls_performed=%x pos=%ld\n", ctx->calls_performed, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, calls_performed, &ctx->calls_performed, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"domain=%d pos=%ld\n", ctx->domain, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, domain, &ctx->domain, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"type=%d pos=%ld\n", ctx->type, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, type, &ctx->type, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"protocol=%d pos=%ld\n", ctx->protocol, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, protocol, &ctx->protocol, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"bind_sa_req pos=%zd\n", *pos);
    if( ctx->bind_sa_req != NULL &&
    	0 > _muacc_push_tlv(buf, pos, len, bind_sa_req,		ctx->bind_sa_req, 		ctx->bind_sa_req_len        ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"bind_sa_res pos=%zd\n", *pos);
	if( ctx->bind_sa_suggested != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, bind_sa_res,		ctx->bind_sa_suggested,		ctx->bind_sa_suggested_len        ) ) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_sas pos=%zd\n", *pos);
	if( ctx->remote_sa != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, remote_sa,  	ctx->remote_sa, 	ctx->remote_sa_len      ) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_hostname pos=%zd\n", *pos);
	if( ctx->remote_hostname != NULL && /* strlen(NULL) might have undesired side effects… */
		0 > _muacc_push_tlv(buf, pos, len, remote_hostname,	ctx->remote_hostname, strlen(ctx->remote_hostname)+1) ) goto _muacc_pack_ctx_err;
    
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_addrinfo_hint pos=%zd\n", *pos);
	if( 0 > _muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_hint, ctx->remote_addrinfo_hint) ) goto _muacc_pack_ctx_err;
	
	DLOG(CLIB_CTX_NOISY_DEBUG2,"remote_addrinfo_res pos=%zd\n", *pos);
	if( 0 > _muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_res,  ctx->remote_addrinfo_res ) ) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"sockopts_current pos=%zd\n", *pos);
	if( 0 > _muacc_push_socketopt_tlv(buf, pos, len, sockopts_current,  ctx->sockopts_current ) ) goto _muacc_pack_ctx_err;

	DLOG(CLIB_CTX_NOISY_DEBUG2,"sockopts_suggested pos=%zd\n", *pos);
	if( 0 > _muacc_push_socketopt_tlv(buf, pos, len, sockopts_suggested,  ctx->sockopts_suggested ) ) goto _muacc_pack_ctx_err;

	return ( *pos - pos0 );
	
_muacc_pack_ctx_err:

	return(-1);
	
}


int _muacc_unpack_ctx(muacc_tlv_t tag, const void *data, size_t data_len, struct _muacc_ctx *_ctx)
{
	struct addrinfo *ai;
	struct sockaddr *sa;
	struct socketopt *so;
	char *str;


	switch(tag) 
	{
		case ctxid:
			if(_ctx->ctxid == -1)
			{
				DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking ctxid\n");
				_ctx->ctxid = *((muacc_ctxid_t *) data);
			}
			else if (_ctx->ctxid == *((muacc_ctxid_t *) data))
			{
				DLOG(CLIB_CTX_NOISY_DEBUG2, "ctxid check ok\n");
			}
			else
			{
				DLOG(CLIB_CTX_NOISY_DEBUG0, "ctxid check failed - wrong context?\n");
				return(-1);
			}
			break;
		case calls_performed:
				DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking calls_performed\n");
				_ctx->calls_performed = *(int *) data;
				break;
		case domain:
				DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking domain\n");
				_ctx->domain = *(int *) data;
				break;
		case type:
				DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking type\n");
				_ctx->type = *(int *) data;
				break;
		case protocol:
				DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking protocol\n");
				_ctx->protocol = *(int *) data;
				break;
		case bind_sa_req:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking bind_sa_req\n");
			if ((int) _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_req);
				_ctx->bind_sa_req = sa;
				_ctx->bind_sa_req_len = data_len;
			}
			else
				return(-1);
			break;
		case bind_sa_res:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking bind_sa_res\n");
			if((int) _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_suggested);
				_ctx->bind_sa_suggested = sa;
				_ctx->bind_sa_suggested_len = data_len;
			}
			else
				return(-1);
			break;
		case remote_sa:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_sa\n");
			if((int) _muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->remote_sa);
				_ctx->remote_sa = sa;
				_ctx->remote_sa_len = data_len;
			}
			else
				return(-1);
			break;
		case remote_hostname:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_hostname\n");
			if((str = malloc(data_len)) != NULL)
			{
				strncpy(str, data, data_len);
				str[data_len-1] = 0x00;
				_ctx->remote_hostname = str;
			}
			else
				return -1;
			break;
		case remote_addrinfo_hint:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_addrinfo_hint\n");
			if((int) _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_hint);
				_ctx->remote_addrinfo_hint = ai;
			}
			else
				return(-1);
			break;

		case remote_addrinfo_res:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking remote_addrinfo_res\n");
			if((int) _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_res);
				_ctx->remote_addrinfo_res = ai;
			}
			else
				return(-1);
			break;

		case sockopts_current:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking sockopts_current\n");
			if((int) _muacc_extract_socketopt_tlv( data, data_len, &so) > 0)
			{
				_muacc_free_socketopts(_ctx->sockopts_current);
				_ctx->sockopts_current = so;
			}
			else
				return(-1);
			break;

		case sockopts_suggested:
			DLOG(CLIB_CTX_NOISY_DEBUG2, "unpacking sockopts_suggested\n");
			if((int) _muacc_extract_socketopt_tlv( data, data_len, &so) > 0)
			{
				_muacc_free_socketopts(_ctx->sockopts_suggested);
				_ctx->sockopts_suggested = so;
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
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tctxid = (%6d,%6d ),\n", (uint32_t) (_ctx->ctxid>>32), (uint32_t) _ctx->ctxid & (0x00000000ffffffff));
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tcalls_performed = %x,\n", _ctx->calls_performed);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tdomain = %d,\n", _ctx->domain);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\ttype = %d,\n", _ctx->type);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tprotocol = %d,\n", _ctx->protocol);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tbind_sa_req = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, _ctx->bind_sa_req, _ctx->bind_sa_req_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tbind_sa_suggested = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, _ctx->bind_sa_suggested, _ctx->bind_sa_suggested_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_hostname = %s,\n", _ctx->remote_hostname);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_addrinfo_hint = ");
		_muacc_print_addrinfo(buf, buf_pos, buf_len, _ctx->remote_addrinfo_hint);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_addrinfo_res = ");
		_muacc_print_addrinfo(buf, buf_pos, buf_len, _ctx->remote_addrinfo_res);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tremote_sa = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, _ctx->remote_sa, _ctx->remote_sa_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tsockopts_current = ");
		_muacc_print_socket_options(buf, buf_pos, buf_len, _ctx->sockopts_current);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ",\n");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\tsockopts_suggested = ");
		_muacc_print_socket_options(buf, buf_pos, buf_len, _ctx->sockopts_suggested);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "\n}\n");

}
