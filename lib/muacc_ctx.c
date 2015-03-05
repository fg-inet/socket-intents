#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "clib/dlog.h"

#include "muacc_ctx.h"
#include "muacc_tlv.h"
#include "clib/muacc_util.h"

#ifndef MUACC_CTX_NOISY_DEBUG0
#define MUACC_CTX_NOISY_DEBUG0 1
#endif

#ifndef MUACC_CTX_NOISY_DEBUG1
#define MUACC_CTX_NOISY_DEBUG1 0
#endif

#ifndef MUACC_CTX_NOISY_DEBUG2
#define MUACC_CTX_NOISY_DEBUG2 0
#endif

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
	
	DLOG(MUACC_CTX_NOISY_DEBUG1,"created new _ctx=%p successfully  \n", (void *) _ctx);

	return _ctx;
}

void _muacc_print_ctx(strbuf_t *sb, const struct _muacc_ctx *_ctx)
{
		strbuf_printf(sb, "_ctx = {\n");
		char uuid_str[37];
        __uuid_unparse_lower(_ctx->ctxid, uuid_str);
		strbuf_printf(sb, "\tctxid = %s\n", uuid_str);
        strbuf_printf(sb, "\tctxino = 0x%X%X,\n", _ctx->ctxino >> 32,  _ctx->ctxino & 0xFFFFFFFF);
		strbuf_printf(sb, "\tcalls_performed = %x,\n", _ctx->calls_performed);
		strbuf_printf(sb, "\tsockfd = %d,\n", _ctx->sockfd);
		strbuf_printf(sb, "\tdomain = %d,\n", _ctx->domain);
		strbuf_printf(sb, "\ttype = %d,\n", _ctx->type);
		strbuf_printf(sb, "\tprotocol = %d,\n", _ctx->protocol);
		strbuf_printf(sb, "\tbind_sa_req = ");
		_muacc_print_sockaddr(sb, _ctx->bind_sa_req, _ctx->bind_sa_req_len);
		strbuf_printf(sb, ",\n");
		strbuf_printf(sb, "\tbind_sa_suggested = ");
		_muacc_print_sockaddr(sb, _ctx->bind_sa_suggested, _ctx->bind_sa_suggested_len);
		strbuf_printf(sb, ",\n");
		strbuf_printf(sb, "\tremote_hostname = %s,\n", _ctx->remote_hostname);
		strbuf_printf(sb, "\tremote_service = %s,\n", _ctx->remote_service);
		strbuf_printf(sb, "\tremote_addrinfo_hint = ");
		_muacc_print_addrinfo(sb, _ctx->remote_addrinfo_hint);
		strbuf_printf(sb, ",\n");
		strbuf_printf(sb, "\tremote_addrinfo_res = ");
		_muacc_print_addrinfo(sb, _ctx->remote_addrinfo_res);
		strbuf_printf(sb, ",\n");
		strbuf_printf(sb, "\tremote_sa = ");
		_muacc_print_sockaddr(sb, _ctx->remote_sa, _ctx->remote_sa_len);
		strbuf_printf(sb, ",\n");
		strbuf_printf(sb, "\tsockopts_current = ");
		_muacc_print_socket_options(sb, _ctx->sockopts_current);
		strbuf_printf(sb, ",\n");
		strbuf_printf(sb, "\tsockopts_suggested = ");
		_muacc_print_socket_options(sb, _ctx->sockopts_suggested);
		strbuf_printf(sb, "\n}\n");
}

int _muacc_free_ctx (struct _muacc_ctx *_ctx)
{
	DLOG(MUACC_CTX_NOISY_DEBUG2, "trying to free data fields\n");

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
	DLOG(MUACC_CTX_NOISY_DEBUG1, "context successfully freed\n");

	return(0);
}

ssize_t _muacc_pack_ctx(char *buf, ssize_t *pos, ssize_t len, const struct _muacc_ctx *ctx)
{

	ssize_t pos0 = *pos;

	DLOG(MUACC_CTX_NOISY_DEBUG1,"packing _ctx=%p pos=%zd\n", (void *) ctx, *pos);

	DLOG(MUACC_CTX_NOISY_DEBUG2,"ctxid pos=%ld\n", (long) *pos);
    if(	0 > _muacc_push_tlv(buf, pos, len, ctxid, &(ctx->ctxid), sizeof(ctx->ctxid) ) ) goto _muacc_pack_ctx_err;

    DLOG(MUACC_CTX_NOISY_DEBUG2,"ctxino pos=%ld\n", (long) *pos);
    if( 0 > _muacc_push_tlv(buf, pos, len, ctxino, &(ctx->ctxino), sizeof(ctx->ctxino) ) ) goto _muacc_pack_ctx_err;
	
	DLOG(MUACC_CTX_NOISY_DEBUG2,"sockfd pos=%ld\n", (long) *pos);
    if( 0 > _muacc_push_tlv(buf, pos, len, sockfd, &(ctx->sockfd), sizeof(int) ) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"calls_performed=%x pos=%ld\n", ctx->calls_performed, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, calls_performed, &ctx->calls_performed, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"domain=%d pos=%ld\n", ctx->domain, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, domain, &ctx->domain, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"type=%d pos=%ld\n", ctx->type, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, type, &ctx->type, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"protocol=%d pos=%ld\n", ctx->protocol, (long) *pos);
	if ( 0 > _muacc_push_tlv(buf, pos, len, protocol, &ctx->protocol, sizeof(int))) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"bind_sa_req pos=%zd\n", *pos);
    if( ctx->bind_sa_req != NULL &&
    	0 > _muacc_push_tlv(buf, pos, len, bind_sa_req,		ctx->bind_sa_req, 		ctx->bind_sa_req_len        ) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"bind_sa_res pos=%zd\n", *pos);
	if( ctx->bind_sa_suggested != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, bind_sa_res,		ctx->bind_sa_suggested,		ctx->bind_sa_suggested_len        ) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"remote_sas pos=%zd\n", *pos);
	if( ctx->remote_sa != NULL &&
		0 > _muacc_push_tlv(buf, pos, len, remote_sa,  	ctx->remote_sa, 	ctx->remote_sa_len      ) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"remote_hostname pos=%zd\n", *pos);
	if( ctx->remote_hostname != NULL && /* strlen(NULL) might have undesired side effects… */
		0 > _muacc_push_tlv(buf, pos, len, remote_hostname,	ctx->remote_hostname, strlen(ctx->remote_hostname)+1) ) goto _muacc_pack_ctx_err;
  
	DLOG(MUACC_CTX_NOISY_DEBUG2,"remote_service pos=%ld\n", *pos);
	if( ctx->remote_service != NULL && /* strlen(NULL) might have undesired side effects… */
		0 > _muacc_push_tlv(buf, pos, len, remote_service,	ctx->remote_service, strlen(ctx->remote_service)+1) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"remote_addrinfo_hint pos=%zd\n", *pos);
	if( 0 > _muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_hint, ctx->remote_addrinfo_hint) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"remote_addrinfo_res pos=%zd\n", *pos);
	if( 0 > _muacc_push_addrinfo_tlv(buf, pos, len, remote_addrinfo_res,  ctx->remote_addrinfo_res ) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"sockopts_current pos=%zd\n", *pos);
	if( 0 > _muacc_push_socketopt_tlv(buf, pos, len, sockopts_current,  ctx->sockopts_current ) ) goto _muacc_pack_ctx_err;

	DLOG(MUACC_CTX_NOISY_DEBUG2,"sockopts_suggested pos=%zd\n", *pos);
	if( 0 > _muacc_push_socketopt_tlv(buf, pos, len, sockopts_suggested,  ctx->sockopts_suggested ) ) goto _muacc_pack_ctx_err;

	return ( *pos - pos0 );

_muacc_pack_ctx_err:

	return(-1);

}


int _muacc_unpack_ctx(muacc_tlv_t tag, const void *data, ssize_t data_len, struct _muacc_ctx *_ctx)
{
	struct addrinfo *ai;
	struct sockaddr *sa;
	struct socketopt *so;
	char *str;
	
	switch(tag)
	{
		case ctxid:
			if(__uuid_is_null(*((uuid_t *) data)) && _ctx->calls_performed == 0)
			{
				DLOG(MUACC_CTX_NOISY_DEBUG2, "ignoring empty ctxid from first packet\n");
			}
			else if(__uuid_is_null(_ctx->ctxid))
			{
				DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking ctxid\n");
				__uuid_copy(_ctx->ctxid, *((uuid_t *) data));
			}
			else if (__uuid_compare(_ctx->ctxid, *((uuid_t *) data)) == 0)
			{
				DLOG(MUACC_CTX_NOISY_DEBUG2, "ctxid check ok\n");
			}
			else
			{
				DLOG(MUACC_CTX_NOISY_DEBUG0, "ctxid check failed - wrong context?\n");
				return(-1);
			}
			break;
        case ctxino:
                DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking ctxino\n");
                _ctx->ctxino = *((muacc_ctxino_t *) data);
                break;
		case sockfd:
                DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking sockfd\n");
                _ctx->sockfd = *((int *) data);
                break;
		case calls_performed:
				DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking calls_performed\n");
				_ctx->calls_performed = *(int *) data;
				break;
		case action:
				DLOG(MUACC_CTX_NOISY_DEBUG1, "unpacking action=%d\n", *((int *) data));
				break;
		case domain:
				DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking domain\n");
				_ctx->domain = *(int *) data;
				break;
		case type:
				DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking type\n");
				_ctx->type = *(int *) data;
				break;
		case protocol:
				DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking protocol\n");
				_ctx->protocol = *(int *) data;
				break;
		case bind_sa_req:
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking bind_sa_req\n");
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
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking bind_sa_res\n");
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
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking remote_sa\n");
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
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking remote_hostname\n");
			if((str = malloc(data_len)) != NULL)
			{
				strncpy(str, data, data_len);
				str[data_len-1] = 0x00;
				_ctx->remote_hostname = str;
			}
			else
				return -1;
			break;
		case remote_service:
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking remote_service\n");
			if((str = malloc(data_len)) != NULL)
			{
				strncpy(str, data, data_len);
				str[data_len-1] = 0x00;
				_ctx->remote_service = str;
			}
			else
				return -1;
			break;
		case remote_addrinfo_hint:
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking remote_addrinfo_hint\n");
			if((int) _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_hint);
				_ctx->remote_addrinfo_hint = ai;
			}
			else
				return(-1);
			break;

		case remote_addrinfo_res:
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking remote_addrinfo_res\n");
			if((int) _muacc_extract_addrinfo_tlv( data, data_len, &ai) > 0)
			{
				freeaddrinfo(_ctx->remote_addrinfo_res);
				_ctx->remote_addrinfo_res = ai;
			}
			else
				return(-1);
			break;

		case sockopts_current:
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking sockopts_current\n");
			if((int) _muacc_extract_socketopt_tlv( data, data_len, &so) > 0)
			{
				_muacc_free_socketopts(_ctx->sockopts_current);
				_ctx->sockopts_current = so;
			}
			else
				return(-1);
			break;

		case sockopts_suggested:
			DLOG(MUACC_CTX_NOISY_DEBUG2, "unpacking sockopts_suggested\n");
			if((int) _muacc_extract_socketopt_tlv( data, data_len, &so) > 0)
			{
				_muacc_free_socketopts(_ctx->sockopts_suggested);
				_ctx->sockopts_suggested = so;
			}
			else
				return(-1);
			break;

		default:
			DLOG(MUACC_CTX_NOISY_DEBUG0, "_muacc_unpack_ctx: ignoring unknown tag %x\n", tag);
				return(-1);
	}

	return(0);
}
