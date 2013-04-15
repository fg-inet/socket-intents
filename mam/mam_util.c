#include <stdio.h>
#include <stdlib.h>
#include <ltdl.h>
#include <assert.h>

#include "mam_util.h"

#include "../lib/muacc_util.h"
#include "../lib/muacc_tlv.h"
#include "../lib/muacc_ctx.h"
#include "../lib/dlog.h"

#ifndef MAM_UTIL_NOISY_DEBUG0
#define MAM_UTIL_NOISY_DEBUG0 0
#endif

#ifndef MAM_UTIL_NOISY_DEBUG1
#define MAM_UTIL_NOISY_DEBUG1 0
#endif

#ifndef MAM_UTIL_NOISY_DEBUG2
#define MAM_UTIL_NOISY_DEBUG2 0
#endif

size_t _mam_print_sockaddr_list(char *buf, size_t *buf_pos, size_t buf_len, const struct sockaddr_list *list)
{
	size_t old_pos = *buf_pos;
	const struct sockaddr_list *current = list;

	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "{ ");

	while (current != NULL)
	{
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "\n\t\t{ ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, current->addr, current->addr_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "if_name = %s, ", current->if_name);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "if_flags = %d, ", current->if_flags);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), " }, ");
		current = current->next;
	}
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "NULL }");
	return *buf_pos - old_pos;
}

size_t _mam_print_prefix_list(char *buf, size_t *buf_pos, size_t buf_len, const struct src_prefix_list *prefixes)
{
	size_t old_pos = *buf_pos;
	const struct src_prefix_list *current = prefixes;

	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "{ ");

	while (current != NULL)
	{
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "\n\t{ ");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "if_addrs = ");
		_mam_print_sockaddr_list(buf, buf_pos, buf_len, current->if_addrs);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "if_netmask = ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, current->if_netmask, current->if_netmask_len);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "}, ");
		current = current->next;
	}
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "NULL }");

	return *buf_pos - old_pos;
}

size_t _mam_print_ctx(char *buf, size_t *buf_pos, size_t buf_len, const struct mam_context *ctx)
{
	size_t old_pos = *buf_pos;

	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "ctx = {\n");
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "\tusage = %d\n", ctx->usage);
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "\tsrc_prefix_list = ");
	_mam_print_prefix_list(buf, buf_pos, buf_len, ctx->prefixes);
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "\n");
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "\tpolicy = ");
	if (ctx->policy != 0)
	{
		const lt_dlinfo *policy_info = lt_dlgetinfo(ctx->policy);
		if (policy_info != NULL )
		{
			if (policy_info->name != NULL && policy_info->filename != NULL)
			{
				*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "%s (%s)", policy_info->name, policy_info->filename);
			}
			else if (policy_info->filename != NULL)
			{
				*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "%s", policy_info->filename);
			}
			else
			{
				*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "(Cannot display module name)");
			}
		}
		else
		{
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "(Error fetching module information)");
		}
	}
	else
	{
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "0");
	}
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "\n");
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "}\n");

	return *buf_pos - old_pos;
}

int _mam_free_ctx(struct mam_context *ctx)
{
	DLOG(MAM_UTIL_NOISY_DEBUG2, "freeing mam_context %p\n",(void *) ctx);
	if (ctx == NULL)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG1, "tried to free NULL context\n");
		return -1;
	}

	_free_src_prefix_list(ctx->prefixes);
	free(ctx);

	return 0;
}

int _mam_fetch_policy_function(lt_dlhandle policy, const char *name, void **function)
{
	if (policy == 0 || name == NULL || function == NULL)
	{
		return -1;
	}

	const char *ltdl_error = NULL;

	DLOG(MAM_UTIL_NOISY_DEBUG2, "Trying to find original function %s\n", name);
	lt_dlerror();
	*function = lt_dlsym(policy, name);

	if (NULL != (ltdl_error = lt_dlerror()))
	{
		/* Error occured */
		DLOG(MAM_UTIL_NOISY_DEBUG1, "Function %s not found:\t%s\n", name, ltdl_error);
		return -1;
	}

	return 0;
}

int _muacc_send_ctx_event(request_context_t *ctx, muacc_mam_action_t reason)
{

	struct evbuffer_iovec v[1];
	size_t ret = 0;
	size_t pos = 0;

	/* Reserve space */
	DLOG(MAM_UTIL_NOISY_DEBUG2,"reserving buffer\n");

	ret = evbuffer_reserve_space(ctx->out, MUACC_TLV_MAXLEN, v, 1);
	if(ret <= 0)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG0,"ERROR reserving buffer\n");
		return(-1);
	}

	DLOG(MAM_UTIL_NOISY_DEBUG1, "packing request\n");

	/* pack request */
	if( 0 > _muacc_push_tlv(v[0].iov_base, &pos, v[0].iov_len, action, &reason, sizeof(muacc_mam_action_t)) ) goto  _muacc_send_ctx_event_pack_err;
	if( 0 > _muacc_pack_ctx(v[0].iov_base, &pos, v[0].iov_len, ctx->ctx) ) goto  _muacc_send_ctx_event_pack_err;
	if( 0 > _muacc_push_tlv_tag(v[0].iov_base, &pos, v[0].iov_len, eof) ) goto  _muacc_send_ctx_event_pack_err;
	DLOG(MAM_UTIL_NOISY_DEBUG2,"packing request done\n");

   v[0].iov_len = pos;


	DLOG(MAM_UTIL_NOISY_DEBUG1,"committing buffer\n");
	if (evbuffer_commit_space(ctx->out, v, 1) < 0)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG0,"ERROR committing buffer\n");
	    return(-1); /* Error committing */
	}
	else
	{
		DLOG(MAM_UTIL_NOISY_DEBUG2,"committed buffer - finished sending request\n");
	    return(0);
	}

	_muacc_send_ctx_event_pack_err:
		return(-1);
}


int _muacc_proc_tlv_event(request_context_t *ctx)
{

	unsigned char *buf;
	size_t buf_pos = 0;

	size_t tlv_len;
	muacc_tlv_t *tag;
	void *data;
	size_t *data_len;

	/* check header */
	tlv_len = sizeof(muacc_tlv_t) + sizeof(size_t);
    buf = evbuffer_pullup(ctx->in, tlv_len);
	if(buf == NULL)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG1, "header read failed: buffer too small - please try again later\n");
		return(_muacc_proc_tlv_event_too_short);
	}
	assert(evbuffer_get_length(ctx->in) >= tlv_len );

	/* parse tag and length */
	tag = ((muacc_tlv_t *) (buf + buf_pos));
	buf_pos += sizeof(muacc_tlv_t);

	data_len = ((size_t *) (buf + buf_pos));
	buf_pos += sizeof(size_t);

	DLOG(MAM_UTIL_NOISY_DEBUG2, "read header - buf_pos=%ld tag=%x, data_len=%ld tlv_len=%ld \n" , (long int) buf_pos, *tag, (long int) *data_len, (long int) tlv_len);

	/* check eof */
	if(*tag == eof)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG2, "found eof - returning\n");
        evbuffer_drain(ctx->in, tlv_len);
		return(_muacc_proc_tlv_event_eof);
	}

	/* check data */
	tlv_len += *data_len;
    buf = evbuffer_pullup(ctx->in, tlv_len);
	if(buf == NULL)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG1, "header read failed: buffer too small - please try again later\n");
		return(_muacc_proc_tlv_event_too_short);
	}
	assert(evbuffer_get_length(ctx->in) >= tlv_len );
	data = ((void *) (buf + buf_pos));

	/* check action */
	if(*tag == action)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG2, "unpacking action: %d \n" , *((muacc_mam_action_t *) data));
		ctx->action = *((muacc_mam_action_t *) data);
	}
	else
	{
		/* process tlv */
		switch( _muacc_unpack_ctx(*tag, data, *data_len, ctx->ctx) )
		{
			case 0:
				DLOG(MAM_UTIL_NOISY_DEBUG1, "parsing TLV successful\n");
				break;
			default:
				DLOG(MAM_UTIL_NOISY_DEBUG0, "WARNING: parsing TLV failed: tag=%d data_len=%ld\n", (int) *tag, (long) *data_len);
				break;
		}
	}

    evbuffer_drain(ctx->in, tlv_len);
	return(tlv_len);

}


