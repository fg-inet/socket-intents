#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>

#include "../config.h"

#include "muacc.h"
#include "tlv.h"
#include "dlog.h"

/** Linked list of socket options */
typedef struct socketopt {
	int 				level;				/**> Level at which the socket option is valid */
	int 				optname;			/**> Identifier of the option */
	void 				*optval;			/**> Pointer to the value */
	socklen_t 			optlen;				/**> Length of the value */
	struct socketopt 	*next;				/**> Pointer to the next socket option */
} socketopt_t;

/** Internal muacc context struct */
struct _muacc_ctx {
	int usage;                          	/**> reference counter */
	uint8_t locks;                      	/**> lock to avoid multiple concurrent requests to MAM */
	int mamsock;                        	/**> socket to talk to MAM */
	int flags;								/**> flags of the context */
	struct sockaddr *bind_sa_req;       	/**> local address requested */
	socklen_t 		 bind_sa_req_len;      	/**> length of bind_sa_req*/
	struct sockaddr *bind_sa_res;       	/**> local address choosen by MAM */
	socklen_t 		 bind_sa_res_len;      	/**> length of bind_sa_res*/
	struct sockaddr *remote_sa_req;     	/**> remote address requested */
	socklen_t 		 remote_sa_req_len;    	/**> length of remote_sa_req*/
	char 			*remote_hostname;      	/**> hostname to resolve */
	struct addrinfo	*remote_addrinfo_hint;	/**> hints for resolving */
	struct addrinfo	*remote_addrinfo_res;	/**> candidate remote addresses (sorted by MAM preference) */
	struct sockaddr *remote_sa_res;     	/**> remote address choosen in the end */
	socklen_t 		 remote_sa_res_len;    	/**> length of remote_sa_res */
	socketopt_t		*socket_options;		/**> associated socket options */
};

/** Helper doing locking simulation - lock part
 * 
 * just to make sure that we have no 
 * interleaving requests on a single socket
 */
int _lock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(_ctx->locks++) );
}

/** Helper doing locking simulation - unlock part
 * 
 * just to make sure that we have no 
 * interleaving requests on a single socket
 */
int _unlock_ctx (struct _muacc_ctx *_ctx)
{
	return( -(--(_ctx->locks)) );
}

/** helper to deep copy addrinfo sockaddr
 *
 */
struct sockaddr *_muacc_clone_sockaddr(const struct sockaddr *src, size_t src_len)
{
	struct sockaddr *ret = NULL;
	
	if(src == NULL)
		return(NULL);

	if((ret = malloc(src_len)) == NULL)
		return NULL;

	memcpy(ret, src, src_len);
	
	return(ret);
}




/** helper to clone a cstring
 *
 */
char *_muacc_clone_string(const char *src)
 {
	 char* ret = NULL;
		 
	 if ( src != NULL)
	 {
	 	size_t sl = strlen(src)+1;
	 	if( ( ret = malloc(sl) ) == NULL )
	 		return(NULL);
	 	memcpy( ret, src, sl);
	 	ret[sl] = 0x00;
	 }
	 
	 return(ret);
 }


/** helper to deep copy addrinfo structs
 *
 */
struct addrinfo *_muacc_clone_addrinfo(const struct addrinfo *src)
{
	struct addrinfo *res = NULL;
	struct addrinfo **cur = &res;

    const struct addrinfo *ai;

	if(src == NULL)
		return(NULL);
	
	for (ai = src; ai; ai = ai->ai_next)
	{
		/* allocate memory and copy */
		if( (*cur = malloc(sizeof(struct addrinfo))) == NULL )
			goto _muacc_clone_addrinfo_malloc_err;
		memcpy( *cur, ai, sizeof(struct addrinfo));

		if ( ai->ai_addr != NULL)
		{
			(*cur)->ai_addr = _muacc_clone_sockaddr(ai->ai_addr, ai->ai_addrlen);
			if((*cur)->ai_addr == NULL)
				goto _muacc_clone_addrinfo_malloc_err;
		}

		if ( ai->ai_canonname != NULL)
		{
			if( ( (*cur)->ai_canonname = _muacc_clone_string(ai->ai_canonname)) == NULL )
				goto _muacc_clone_addrinfo_malloc_err;
		}

		cur = &((*cur)->ai_next);

	}

	return res;

	_muacc_clone_addrinfo_malloc_err:
	fprintf(stderr, "%6d: _muacc_clone_addrinfo failed to allocate memory\n", (int) getpid());
	return NULL;

}

/** helper to deep copy socketopt linked lists
 *
 */
struct socketopt *_muacc_clone_socketopts(const struct socketopt *src)
{
	struct socketopt *ret = NULL;

	if (src == NULL)
		return NULL;

	if ((ret = malloc(sizeof(struct socketopt))) == NULL)
	{
		fprintf(stderr, "%6d: _muacc_clone_socketopts failed to allocate memory.\n", (int) getpid());
		return NULL;
	}
	else
	{
		memcpy(ret, src, sizeof(struct socketopt));

		const struct socketopt *srccurrent = src;
		struct socketopt *dstcurrent = ret;
		struct socketopt *new = NULL;

		while (srccurrent->next != NULL)
		{
			if ((new = malloc(sizeof(struct socketopt))) == NULL)
			{
				fprintf(stderr, "%6d: _muacc_clone_socketopts failed to allocate memory.\n", (int) getpid());
				return NULL;
			}
			else
			{
				dstcurrent-> next = new;
				memcpy(new, srccurrent->next, sizeof(struct socketopt));
				srccurrent = srccurrent->next;
				dstcurrent = dstcurrent->next;
			}
		}
	}

	return ret;
}

int muacc_release_context(struct muacc_context *ctx)
{
	if(ctx == NULL)
	{
		DLOG(CLIB_NOISY_DEBUG, "WARNING: tried to release NULL POINTER context\n");		
		return -1;
	}
	else if(ctx->ctx == NULL)
	{
		DLOG(CLIB_NOISY_DEBUG, "empty context - nothing to release\n");
		return 0;
	}		
	else if( --(ctx->ctx->usage) == 0 )
	{
		DLOG(CLIB_NOISY_DEBUG, "trying to free data fields\n");		
		
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
	
	DLOG(CLIB_NOISY_DEBUG, "context successfully freed\n");
	
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

/* Helper making a connection to MAM */
int _connect_ctx_to_mam(struct _muacc_ctx *_ctx) 
{
	
	struct sockaddr_un mams;
	mams.sun_family = AF_UNIX;
	#ifdef HAVE_SOCKADDR_LEN
	mams.sun_len = sizeof(struct sockaddr_un);
	#endif
	strncpy( mams.sun_path, MUACC_SOCKET, sizeof(mams.sun_path));
	
	_ctx->mamsock = socket(PF_UNIX, SOCK_STREAM, 0);
	if(_ctx->mamsock == -1)
	{
		DLOG(CLIB_NOISY_DEBUG, "socket creation failed: %s\n", strerror(errno));		
		return(-errno);	
	}
	
	if(connect(_ctx->mamsock, (struct sockaddr*) &mams, sizeof(mams)) < 0)
	{
		DLOG(CLIB_NOISY_DEBUG, "connect to mam via %s failed: %s\n",  mams.sun_path, strerror(errno));
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
	
	/* connect to MAM */
	if(_connect_ctx_to_mam(_ctx))
	{
		/* free context backing struct */
		free(_ctx);
	
		/* declare interface struct invalid */
		ctx->ctx = NULL;
		return(-1);	
	}

	DLOG(CLIB_NOISY_DEBUG,"conected & context successfully initalized\n");

	ctx->ctx = _ctx;
	return(0);
}

int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src) 
{
	struct _muacc_ctx *_ctx;
	
	if(src->ctx == NULL)
	{
		DLOG(CLIB_NOISY_DEBUG,"warning: cloning uninitalized context\n");
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


/** Helper serialzing _ctx in TLVs
 *
 */
size_t _muacc_pack_ctx(char *buf, size_t *pos, size_t len, struct _muacc_ctx *ctx) 
{

	size_t pos0 = *pos;
	
    if( ctx->bind_sa_req != NULL &&
    	0 > muacc_push_tlv(buf, pos, len, bind_sa_req,		ctx->bind_sa_req, 		ctx->bind_sa_req_len        ) ) goto _muacc_pack_ctx_err;
	if( ctx->bind_sa_res != NULL &&
		0 > muacc_push_tlv(buf, pos, len, bind_sa_res,		ctx->bind_sa_res,		ctx->bind_sa_res_len        ) ) goto _muacc_pack_ctx_err;
	if( ctx->remote_sa_req != NULL &&
		0 > muacc_push_tlv(buf, pos, len, remote_sa_req,  	ctx->remote_sa_req, 	ctx->remote_sa_req_len      ) ) goto _muacc_pack_ctx_err;
	if( ctx->remote_sa_res != NULL &&
		0 > muacc_push_tlv(buf, pos, len, remote_sa_res,  	ctx->remote_sa_res, 	ctx->remote_sa_res_len      ) ) goto _muacc_pack_ctx_err;
	if( ctx->remote_hostname != NULL && /* strlen(NULL) might have undesired side effects… */
		0 > muacc_push_tlv(buf, pos, len, remote_hostname,	ctx->remote_hostname, strlen(ctx->remote_hostname)) ) goto _muacc_pack_ctx_err;
    if( 0 > muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_hint, ctx->remote_addrinfo_hint) ) goto _muacc_pack_ctx_err;
	if( 0 > muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_res,  ctx->remote_addrinfo_res ) ) goto _muacc_pack_ctx_err;

	return ( *pos - pos0 );
	
_muacc_pack_ctx_err:

	return(-1);
	
}


/** Helper parsing a single TLV and pushing the data to _ctx
 *
 * keeps memory consistent
 */
int _muacc_unpack_ctx(muacc_tlv_t tag, const void *data, size_t data_len, struct _muacc_ctx *_ctx)
{
	struct addrinfo *ai;
	struct sockaddr *sa;
	char *str;


	switch(tag) 
	{
		case bind_sa_req:
			DLOG(CLIB_NOISY_DEBUG, "unpacking bind_sa_req\n");
			if( muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_req);
				_ctx->bind_sa_req = sa;
			}
			else
				return(-1);
			break;
		case bind_sa_res:
			DLOG(CLIB_NOISY_DEBUG, "unpacking bind_sa_res\n");
			if( muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->bind_sa_res);
				_ctx->bind_sa_res = sa;
			}
			else
				return(-1);
			break;
		case remote_sa_req:
			DLOG(CLIB_NOISY_DEBUG, "unpacking remote_sa_req\n");
			if( muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->remote_sa_req);
				_ctx->remote_sa_req = sa;
			}
			else
				return(-1);
			break;
		case remote_sa_res:
			DLOG(CLIB_NOISY_DEBUG, "unpacking remote_sa_res\n");
			if( muacc_extract_socketaddr_tlv(data, data_len, &sa) > 0)
			{
				free(_ctx->remote_sa_res);
				_ctx->remote_sa_res = sa;
			}
			else
				return(-1);
			break;
		case remote_hostname:
			DLOG(CLIB_NOISY_DEBUG, "unpacking remote_hostname\n");
			if((str = malloc(data_len)) != NULL)
			{
				str[data_len-1] = 0x00;
				_ctx->remote_hostname = str;
			}
			else
				return -1;
			break;
		case remote_addrinfo_hint:
			DLOG(CLIB_NOISY_DEBUG, "unpacking remote_addrinfo_hint\n");
			if( muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_hint);
				_ctx->remote_addrinfo_hint = ai;
			}
			else
				return(-1);
			break;

		case remote_addrinfo_res:
			DLOG(CLIB_NOISY_DEBUG, "unpacking remote_addrinfo_res\n");
			if( muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_res);
				_ctx->remote_addrinfo_res = ai;
			}
			else
				return(-1);
			break;

		default:
			fprintf(stderr, "_muacc_unpack_ctx: ignoring unknown tag %x\n", tag);
			break;
	}

	return(0);

} 


/** Helper which sends contents of the context to the MAM and replaces it with the values from the response
 *
 */
int _muacc_contact_mam (muacc_mam_action_t reason, struct _muacc_ctx *_ctx)
{
	
	char buf[MUACC_TLV_LEN];
	size_t pos = 0;
	size_t ret = 0;
	muacc_tlv_t tag;
	void *data;
	size_t data_len;
	
	DLOG(CLIB_NOISY_DEBUG, "packing request");
	
	/* pack request */
	if( 0 > muacc_push_tlv(buf, &pos, sizeof(buf), action, &reason, sizeof(muacc_mam_action_t)) ) goto  _muacc_contact_mam_pack_err;
	if( 0 > _muacc_pack_ctx(buf, &pos, sizeof(buf), _ctx) ) goto  _muacc_contact_mam_pack_err;
	if( 0 > muacc_push_tlv_tag(buf, &pos, sizeof(buf), eof) ) goto  _muacc_contact_mam_pack_err;
	DLOG(CLIB_NOISY_DEBUG," done\n");

	
	/* send requst */
	if( 0 > (ret = send(_ctx->mamsock, buf, pos, 0)) )
	{
		fprintf(stderr, "%6d: _muacc_contact_mam: error sending request: %s\n", (int) getpid(), strerror(errno));
		return(-1);
	}
	else
 	{
		DLOG(CLIB_NOISY_DEBUG, "request sent  - %ld of %ld bytes\n", (long int) ret, (long int) pos);
 	}
	
	/* read & unpack response */
	DLOG(CLIB_NOISY_DEBUG, "processing response:\n");
	pos = 0;
	while( (ret = muacc_read_tlv(_ctx->mamsock, buf, &pos, sizeof(buf), &tag, &data, &data_len)) > 0) 
	{
		DLOG(CLIB_NOISY_DEBUG, "\tpos=%ld tag=%x, len=%ld\n", (long int) pos, tag, (long int) data_len);
		if( tag == eof )
			break;
		else if ( 0 > _muacc_unpack_ctx(tag, data, data_len, _ctx) )
			goto  _muacc_contact_mam_parse_err;
	}
	DLOG(CLIB_NOISY_DEBUG, "processing response done: pos=%li last_res=%li done\n", (long int) pos, (long int) ret);
	return(0);


_muacc_contact_mam_pack_err:

	DLOG(CLIB_NOISY_DEBUG, "failed to pack request\n");
	return(-1);
	
_muacc_contact_mam_parse_err:

	DLOG(CLIB_NOISY_DEBUG, "failed to process response\n");
	return(-1);
	
}


int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res)		
{
	
	if(ctx->ctx == 0)
	{
		DLOG(CLIB_NOISY_DEBUG, "context uninialized - fallback to regual connect\n");
		goto muacc_getaddrinfo_fallback;
	}

	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_NOISY_DEBUG, "context already in use - fallback to regual connect\n");
		_unlock_ctx(ctx->ctx);
		goto muacc_getaddrinfo_fallback;
	}
	
	/* ToDo: Involve MAM
	 *
	 */

	_unlock_ctx(ctx->ctx);
	
muacc_getaddrinfo_fallback:

	return getaddrinfo(hostname, servname, hints, res);	
		
}


int muacc_setsockopt(struct muacc_context *ctx, int socket, int level, int option_name,
    const void *option_value, socklen_t option_len)
{	
	
	if( ctx->ctx == 0 )
	{
		DLOG(CLIB_NOISY_DEBUG, "context uninialized - fallback to regual setsockopt\n");
		goto muacc_setsockopt_fallback;
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_NOISY_DEBUG, "context already in use - fallback to regual setsockopt\n");
		_unlock_ctx(ctx->ctx);
		goto muacc_setsockopt_fallback;
	}
	
	struct socketopt *newopt = malloc(sizeof(struct socketopt));
	newopt->level = level;
	newopt->optname = option_name;
	newopt->optlen = option_len;
	newopt->optval = malloc(option_len);
	memcpy(newopt->optval, option_value, option_len);

	struct socketopt *current = ctx->ctx->socket_options;
	while (current != NULL)
		current = current->next;
	
	current = newopt;

	/* ToDo: encode sockopt for MAM
	 *
	 */

	_unlock_ctx(ctx->ctx);
		
muacc_setsockopt_fallback:
	
	return setsockopt(socket, level, option_name, option_value, option_len);
		
}

int muacc_connect(struct muacc_context *ctx,
	    int socket, const struct sockaddr *address, socklen_t address_len)
{	
	DLOG(CLIB_NOISY_DEBUG, "invoked\n");
	
	if( ctx->ctx == 0 )
	{
		DLOG(CLIB_NOISY_DEBUG, "context uninialized - fallback to regual connect\n");
		goto muacc_connect_fallback;
	}
	
	if( _lock_ctx(ctx->ctx) )
	{
		DLOG(CLIB_NOISY_DEBUG, "context already in use - fallback to regual connect\n");
		_unlock_ctx(ctx->ctx);
		goto muacc_connect_fallback;
	}
	
	ctx->ctx->remote_sa_req     = _muacc_clone_sockaddr(address, address_len);
	ctx->ctx->remote_sa_req_len = address_len;
	
	if(ctx->ctx->remote_sa_res == NULL)
	{
		/* set default request as default */
		ctx->ctx->remote_sa_res 	= _muacc_clone_sockaddr(address, address_len);
		ctx->ctx->remote_sa_res_len	= address_len;
	}
	
	if( _muacc_contact_mam(muacc_action_connect, ctx->ctx) <0 ){
		_unlock_ctx(ctx->ctx);
		DLOG(CLIB_NOISY_DEBUG, "got no response from mam - fallback to regual connect\n");
		goto muacc_connect_fallback;
	}
	
	_unlock_ctx(ctx->ctx);
	
	return connect(socket, ctx->ctx->remote_sa_res, ctx->ctx->remote_sa_res_len);
	
	
muacc_connect_fallback:
	
	return connect(socket, address, address_len);
		
}			
