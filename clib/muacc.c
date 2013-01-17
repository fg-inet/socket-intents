#include "muacc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include "../config.h"

struct _muacc_ctx {
	int usage;                          	/* referance counter */
	uint8_t locks;                      	/* lock to avoid multiple concurrent requests to mam */
	int mamsock;                        	/* socket to talk tu mam */
	int flags;								/* flags of the context */
	struct sockaddr *bind_sa_req;       	/* local address requested */
	socklen_t 		 bind_sa_req_len;      	/* */
	struct sockaddr *bind_sa_res;       	/* local address choosen by mam */
	socklen_t 		 bind_sa_res_len;      	/* */
	struct sockaddr *remote_sa_req;     	/* remote address requested */
	socklen_t 		 remote_sa_req_len;    	/* */
	char 			*remote_hostname;      	/* hostname resolved */
	struct addrinfo	*remote_addrinfo_hint;	/* candidate remote addresses (sorted by mam preference) */
	struct addrinfo	*remote_addrinfo_res;	/* candidate remote addresses (sorted by mam preference) */
	struct sockaddr *remote_sa_res;     	/* remote address choosen in the end */
	socklen_t 		 remote_sa_res_len;    	/* */
};

/* locking simulation - just to make sure that we have no 
 * interleaving requests on a single socket
 */
int _lock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(_ctx->locks++) );
}

int _unlock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(--(_ctx->locks)) );
}

/* reference counting based memory management for muacc_context */
int muacc_release_context(struct muacc_context *ctx)
{
	if(ctx->ctx == 0)
	{
		return(-1);
	}
			
	if( --(ctx->ctx->usage) == 0 )
	{
		close(ctx->ctx->mamsock);
		free(ctx->ctx);
	}
	ctx->ctx = NULL;
	
	return(ctx->ctx->usage);
}

/* reference counting based memory management for muacc_context */
int muacc_retain_context(struct muacc_context *ctx)
{
	if(ctx->ctx == 0)
	{
		return(-1);
	}

	return(++(ctx->ctx->usage));
}

/* make a connection to the multi-access manager */
int _connect_ctx_to_mam(struct _muacc_ctx *_ctx) 
{
	
	struct sockaddr_un mams;
	mams.sun_family = AF_UNIX;
	#ifdef HAVE_SOCKADDR_LEN
	mams.sun_len = sizeof(struct sockaddr_un);
	#endif
	strncpy( mams.sun_path, MUACC_SOCKET, sizeof(mams.sun_path));
	
	if(_ctx->mamsock = socket(PF_UNIX, SOCK_STREAM, 0) < 1)
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "_connect_ctx_to_mam socket creation failed", (int) getpid(), strerror(errno));
		#endif
		return(-errno);	
	}
	
	if(connect(_ctx->mamsock, (struct sockaddr*) &mams, sizeof(mams)) < 0)
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: _connect_ctx_to_mam connect to mam via %s failed: %s\n", (int) getpid(),  mams.sun_path, strerror(errno));
		#endif
		return(-errno);	
	}
	
	return 0;
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
	
	/* connect to mam */
	if(_connect_ctx_to_mam)
	{
		/* free context backing struct */
		free(_ctx);
	
		/* declare interface struct invalid */
		ctx->ctx = NULL;
		return(-1);	
	}

	#ifdef CLIB_NOISY_DEBUG
	fprintf(stderr, "%6d: muacc_init_context conect successfully initalized\n", (int) getpid());
	#endif	

	ctx->ctx = _ctx;
	return(0);
}

int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src) 
{
	struct _muacc_ctx *_ctx;
	
	if(src->ctx == NULL)
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_clone_context warning: cloning uninitalized context\n", (int) getpid());
		#endif	
		dst->ctx = NULL;
		return(0);
	}
	
	if( (_ctx = malloc( sizeof(struct _muacc_ctx) )) == NULL ) 
	{
		perror("muacc_clone_context malloc failed");
		return(-1);	
	}
	
	memcpy(_ctx, src->ctx, sizeof(struct _muacc_ctx));
	
	/* connect to mam */
	if(_connect_ctx_to_mam(_ctx))
	{
		/* free context backing struct */
		free(_ctx);
	
		/* declare interface struct invalid */
		dst->ctx = NULL;
		return(-1);	
	}
	
	_ctx->usage = 1;
	dst->ctx = _ctx;
	
	return(0);	
}

size_t _muacc_pack_ctx(char *buf, size_t *pos, size_t len, struct _muacc_ctx *ctx) 
{

	size_t pos0 = *pos;
	
    if( 0 > muacc_push_tlv(buf, pos, len, bind_sa_req,		ctx->bind_sa_req, 		ctx->bind_sa_req_len        ) ) goto _muacc_pack_ctx_err;
    if( 0 > muacc_push_tlv(buf, pos, len, bind_sa_res,		ctx->bind_sa_res,		ctx->bind_sa_res_len        ) ) goto _muacc_pack_ctx_err;
    if( 0 > muacc_push_tlv(buf, pos, len, remote_sa_req,  	ctx->remote_sa_req, 	ctx->remote_sa_req_len      ) ) goto _muacc_pack_ctx_err;
    if( 0 > muacc_push_tlv(buf, pos, len, remote_sa_res,  	ctx->remote_sa_res, 	ctx->remote_sa_res_len      ) ) goto _muacc_pack_ctx_err;
    if( 0 > muacc_push_tlv(buf, pos, len, remote_hostname,	ctx->remote_hostname, 	strlen(ctx->remote_hostname)) ) goto _muacc_pack_ctx_err;

    if( 0 > muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_hint, ctx->remote_addrinfo_hint) ) goto _muacc_pack_ctx_err;
    if( 0 > muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_res,  ctx->remote_addrinfo_res ) ) goto _muacc_pack_ctx_err;
	
	return (*pos-pos0);
	
_muacc_pack_ctx_err:

	return(-1);
	
}

size_t _muacc_unpack_ctx(char *buf, size_t *pos, size_t len, struct _muacc_ctx **ctx)
{
	#warning unimplemented
	
	return -1;
} 


int _muacc_contact_mam (muacc_mam_action_t action, struct _muacc_ctx *ctx) 
{
	
	char buf[MUACC_TLV_LEN];
	size_t pos = 0;
	
	if( 0 > muacc_push_tlv(buf, &pos, sizeof(buf), sizeof(muacc_mam_action_t), &action) ) goto  _muacc_contact_mam_err;
	if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), ctx) ) goto  _muacc_contact_mam_err;
	/* send requst */
	if( 0 > _muacc_unpack_ctx(buf, 0, sizeof(buf), ctx) ) goto  _muacc_contact_mam_err;
	return(0);

_muacc_contact_mam_err:
	return(-1);
	
}

int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res)		
{
	
	if(ctx->ctx == 0)
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_getaddrinfo context uninialized - fallback to regual connect\n", (int) getpid());
		#endif
		goto muacc_getaddrinfo_fallback;
	}

	if( _lock_ctx(ctx->ctx) )
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_getaddrinfo context already in use - fallback to regual connect\n", (int) getpid());
		#endif
		_unlock_ctx(ctx->ctx);
		goto muacc_getaddrinfo_fallback;
	}
	
	_unlock_ctx(ctx->ctx);
	
muacc_getaddrinfo_fallback:

	return getaddrinfo(hostname, servname, hints, res);	
		
}


int muacc_setsockopt(struct muacc_context *ctx, int socket, int level, int option_name,
    const void *option_value, socklen_t option_len)
{	
	
	if( ctx->ctx == 0 )
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_setsockopt context uninialized - fallback to regual setsockopt\n", (int) getpid());
		#endif
		goto muacc_setsockopt_fallback;
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_setsockopt context already in use - fallback to regual setsockopt\n", (int) getpid());
		#endif
		_unlock_ctx(ctx->ctx);
		goto muacc_setsockopt_fallback;
	}
	
	_unlock_ctx(ctx->ctx);
		
muacc_setsockopt_fallback:
	
	return setsockopt(socket, level, option_name, option_value, option_len);
		
}

int muacc_connect(struct muacc_context *ctx,
	    int socket, struct sockaddr *address, socklen_t address_len)
{	
	
	if( ctx->ctx == 0 )
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_connect context uninialized - fallback to regual connect\n", (int) getpid());
		#endif
		goto muacc_connect_fallback;
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_connect context already in use - fallback to regual connect\n", (int) getpid());
		#endif
		_unlock_ctx(ctx->ctx);
		goto muacc_connect_fallback;
	}
	
	ctx->ctx->remote_sa_req     = address;
	ctx->ctx->remote_sa_req_len = address_len;
	
	if( _muacc_contact_mam(muacc_action_connect, ctx->ctx) <0 ){
		_unlock_ctx(ctx->ctx);
		goto muacc_connect_fallback;
	}
	
	return connect(socket, ctx->ctx->remote_sa_res, ctx->ctx->remote_sa_res_len);
	
	_unlock_ctx(ctx->ctx);
	
muacc_connect_fallback:
	
	return connect(socket, address, address_len);
		
}			