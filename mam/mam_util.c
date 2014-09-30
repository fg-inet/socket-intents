#include <stdio.h>
#include <stdlib.h>
#include <ltdl.h>
#include <assert.h>

#include "clib/muacc_util.h"
#include "lib/muacc_tlv.h"
#include "lib/muacc_ctx.h"
#include "clib/dlog.h"
#include "clib/strbuf.h"

#include "mam_util.h"

#ifndef MAM_UTIL_NOISY_DEBUG0
#define MAM_UTIL_NOISY_DEBUG0 0
#endif

#ifndef MAM_UTIL_NOISY_DEBUG1
#define MAM_UTIL_NOISY_DEBUG1 0
#endif

#ifndef MAM_UTIL_NOISY_DEBUG2
#define MAM_UTIL_NOISY_DEBUG2 0
#endif

void _mam_print_sockaddr_list(strbuf_t *sb, const struct sockaddr_list *list)
{
	const struct sockaddr_list *current = list;

	strbuf_printf(sb, "{ ");

	while (current != NULL)
	{
		strbuf_printf(sb, "\n\t\t{ ");
		_muacc_print_sockaddr(sb, current->addr, current->addr_len);
		strbuf_printf(sb, " }, ");
		current = current->next;
	}
	strbuf_printf(sb, "NULL }");
}

void _mam_print_prefix_list_flags(strbuf_t *sb, unsigned int	pfx_flags)
{
	strbuf_printf(sb, "pfx_flags =");
	if(pfx_flags & PFX_ANY			 ) strbuf_printf(sb, " PFX_ANY");
	if(pfx_flags & PFX_ENABLED		 ) strbuf_printf(sb, " PFX_ENABLED");
	if(pfx_flags & PFX_CONF		     ) strbuf_printf(sb, " PFX_CONF");
	if(pfx_flags & PFX_CONF_PFX	     ) strbuf_printf(sb, " PFX_CONF_PFXL");
	if(pfx_flags & PFX_CONF_IF		 ) strbuf_printf(sb, " PFX_CONF_IF");
	if(pfx_flags & PFX_SCOPE_GLOBAL  ) strbuf_printf(sb, " PFX_SCOPE_GLOBAL");
	if(pfx_flags & PFX_SCOPE_LL	     ) strbuf_printf(sb, " PFX_SCOPE_LLL");
	strbuf_printf(sb, ", ");
}

static void _mam_print_dict_kv (gpointer key,  gpointer val, gpointer sb)
{
	strbuf_printf((strbuf_t *) sb, " %s -> %s", (char *) key, (char *) val);
}

void _mam_print_prefix_list(strbuf_t *sb, GSList *prefixes)
{
	GSList *p = prefixes;

	strbuf_printf(sb, "{ ");

	while (p != NULL)
	{
		struct src_prefix_list *current = (struct src_prefix_list *) p->data;
		strbuf_printf(sb, "\n\t");
		_mam_print_prefix(sb, current);
		p = p->next;
	}
	strbuf_printf(sb, "NULL }");

}


void _mam_print_prefix(strbuf_t *sb, struct src_prefix_list *current)
{
	strbuf_printf(sb, "{ ");
	strbuf_printf(sb, " if_name = %s, ", current->if_name);
	_mam_print_prefix_list_flags(sb, current->pfx_flags);
	strbuf_printf(sb, " if_flags = %d, ", current->if_flags);
	strbuf_printf(sb, " if_addrs = ");
	_mam_print_sockaddr_list(sb, current->if_addrs);
	strbuf_printf(sb, " if_netmask = ");
	_muacc_print_sockaddr(sb, current->if_netmask, current->if_netmask_len);
	if(current->policy_set_dict != NULL)
	{
		strbuf_printf(sb, " policy_set_dict = {");
		g_hash_table_foreach(current->policy_set_dict, &_mam_print_dict_kv, sb);
		strbuf_printf(sb, " }");
	}
	strbuf_printf(sb, " }, ");
}

void _mam_print_ctx(strbuf_t *sb, const struct mam_context *ctx)
{
	strbuf_printf(sb, "ctx = {\n");
	strbuf_printf(sb, "\tusage = %d\n", ctx->usage);
	strbuf_printf(sb, "\tsrc_prefix_list = ");
	_mam_print_prefix_list(sb, ctx->prefixes);
	strbuf_printf(sb, "\n");
	if(ctx->policy_set_dict != NULL) 
	{
		strbuf_printf(sb, "\tpolicy_set_dict = {");
		g_hash_table_foreach(ctx->policy_set_dict, &_mam_print_dict_kv, sb);
		strbuf_printf(sb, " }\n");
	}
	strbuf_printf(sb, "\tpolicy = ");
	if (ctx->policy != 0)
	{
		const lt_dlinfo *policy_info = lt_dlgetinfo(ctx->policy);
		if (policy_info != NULL )
		{
			if (policy_info->name != NULL && policy_info->filename != NULL)
			{
				strbuf_printf(sb, "%s (%s)", policy_info->name, policy_info->filename);
			}
			else if (policy_info->filename != NULL)
			{
				strbuf_printf(sb, "%s", policy_info->filename);
			}
			else
			{
				strbuf_printf(sb, "(Cannot display module name)");
			}
		}
		else
		{
			strbuf_printf(sb, "(Error fetching module information)");
		}
	}
	else
	{
		strbuf_printf(sb, "0");
	}
	strbuf_printf(sb, "\n");
	strbuf_printf(sb, "}\n");
}

int _mam_free_ctx(struct mam_context *ctx)
{
	DLOG(MAM_UTIL_NOISY_DEBUG2, "freeing mam_context %p\n",(void *) ctx);
	if (ctx == NULL)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG1, "tried to free NULL context\n");
		return -1;
	}

	g_slist_free_full(ctx->prefixes, &_free_src_prefix_list);
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

	DLOG(MAM_UTIL_NOISY_DEBUG2, "Trying to find function %s\n", name);
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

int _mam_callback_or_fail(request_context_t *ctx, const char *function, unsigned int flag_if_success, muacc_mam_action_t action_if_fail)
{
	if (ctx == NULL || function == NULL)
		return -1;

	int (*callback_function)(request_context_t *ctx, struct event_base *base) = NULL;
	if (_mam_fetch_policy_function(ctx->mctx->policy, function, (void **) &callback_function) == 0)
	{
		int ret;
		DLOG(MAM_UTIL_NOISY_DEBUG2,"Calling %s\n", function);
		ctx->policy_calls_performed |= flag_if_success;
		ret = callback_function(ctx, ctx->mctx->ev_base);
		if (ret != 0)
		{
			DLOG(MAM_UTIL_NOISY_DEBUG1,"Callback %s returned %d\n", function, ret);
			_muacc_send_ctx_event(ctx, action_if_fail);
		}
		return 0;
	}
	else
	{
		DLOG(MAM_UTIL_NOISY_DEBUG2, "No callback %s available. Trying to send back ctx\n", function);
		_muacc_send_ctx_event(ctx, action_if_fail);
		return -1;
	}
}

int _muacc_send_ctx_event(request_context_t *ctx, muacc_mam_action_t reason)
{
	/* Check if we can already send a response */
	if (ctx->action == muacc_act_socketconnect_fallback)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG2,"Socketconnect fallback - checking whether both resolve and connect have been called\n");

		if ((ctx->policy_calls_performed & MAM_POLICY_RESOLVE_CALLED) == 0)
		{
			DLOG(MAM_UTIL_NOISY_DEBUG0,"Calling on_resolve_request for Socketconnect fallback\n");
			return _mam_callback_or_fail(ctx, "on_resolve_request", MAM_POLICY_RESOLVE_CALLED, reason);
		}
		else if ((ctx->policy_calls_performed & MAM_POLICY_CONNECT_CALLED) == 0)
		{
			if (ctx->ctx->remote_sa == NULL)
			{
				// Choose first getaddrinfo result as remote address before invoking connect callback
				ctx->ctx->domain = ctx->ctx->remote_addrinfo_res->ai_family;
				ctx->ctx->type = ctx->ctx->remote_addrinfo_res->ai_socktype;
				ctx->ctx->protocol = ctx->ctx->remote_addrinfo_res->ai_protocol;
				ctx->ctx->remote_sa_len = ctx->ctx->remote_addrinfo_res->ai_addrlen;
				ctx->ctx->remote_sa = _muacc_clone_sockaddr(ctx->ctx->remote_addrinfo_res->ai_addr, ctx->ctx->remote_addrinfo_res->ai_addrlen);
			}
			DLOG(MAM_UTIL_NOISY_DEBUG0,"Calling on_connect_request to complete Socketconnect fallback\n");
			return _mam_callback_or_fail(ctx, "on_connect_request", MAM_POLICY_CONNECT_CALLED, reason);
		}
	}

	DLOG(MAM_UTIL_NOISY_DEBUG0,"Sending response %d to client request\n", reason);
	/* Request has finished - Actually send a reply */
	struct evbuffer_iovec v[1];
	v[0].iov_len = 0;
	ssize_t ret = 0;
	ssize_t pos = 0;

	/* Reserve space */
	DLOG(MAM_UTIL_NOISY_DEBUG2,"reserving buffer\n");

	ret = evbuffer_reserve_space(ctx->out, MUACC_TLV_MAXLEN, v, 1);
	if(ret <= 0)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG1,"ERROR reserving buffer\n");
		mam_release_request_context(ctx);
		return(-1);
	}

	DLOG(MAM_UTIL_NOISY_DEBUG2, "packing request\n");

	/* pack request */
	if( 0 > _muacc_push_tlv(v[0].iov_base, &pos, v[0].iov_len, action, &reason, sizeof(muacc_mam_action_t)) ) goto  _muacc_send_ctx_event_pack_err;

	if (reason == muacc_act_socketchoose_resp_existing && ctx->set != NULL)
	{
		if( 0 > _muacc_push_tlv(v[0].iov_base, &pos, v[0].iov_len, socketset_file, &(ctx->set->file), sizeof(int)) ) goto  _muacc_send_ctx_event_pack_err;
	}

	if( 0 > _muacc_pack_ctx(v[0].iov_base, &pos, v[0].iov_len, ctx->ctx) ) goto  _muacc_send_ctx_event_pack_err;
	if( 0 > _muacc_push_tlv_tag(v[0].iov_base, &pos, v[0].iov_len, eof) ) goto  _muacc_send_ctx_event_pack_err;
	DLOG(MAM_UTIL_NOISY_DEBUG2,"packing request done\n");

   v[0].iov_len = pos;


	DLOG(MAM_UTIL_NOISY_DEBUG2,"committing buffer\n");
	if (evbuffer_commit_space(ctx->out, v, 1) < 0)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG1,"ERROR committing buffer\n");
		mam_release_request_context(ctx);
	    return(-1); /* Error committing */
	}
	else
	{
		DLOG(MAM_UTIL_NOISY_DEBUG2,"committed buffer - finished sending request\n");
		mam_release_request_context(ctx);
	    return(0);
	}

	_muacc_send_ctx_event_pack_err:
		mam_release_request_context(ctx);
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
		DLOG(MAM_UTIL_NOISY_DEBUG1, "TLV read failed: not enough data \n");
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
		DLOG(MAM_UTIL_NOISY_DEBUG1, "TLV read failed: not enough data\n");
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
	else if (*tag == socketset_file)
	{
		DLOG(MAM_UTIL_NOISY_DEBUG2, "socketset file descriptor %d \n" , *((muacc_mam_action_t *) data));
		struct socketset *new = ctx->set;
		while (new != NULL)
		{
			new = new->next;
		}
		new = malloc(sizeof(struct socketset));
		new->next = NULL;
		new->file = *(int *) data;
		new->ctx = NULL;
		ctx->set = new;
	}
	else
	{
		struct _muacc_ctx *parsectx = ctx->ctx;

		if (ctx->set != NULL)
		{
			/* parse incoming context into the socket set */
			struct socketset *sockset = ctx->set;
			while (sockset->next != NULL)
			{
				sockset = sockset->next;
			}
			DLOG(MAM_UTIL_NOISY_DEBUG2, "receiving context for socketset member %d\n", sockset->file);
			if (sockset->ctx == NULL)
			{
				sockset->ctx = _muacc_create_ctx();
			}
			parsectx = sockset->ctx;
		}

		/* unpack context */
		switch( _muacc_unpack_ctx(*tag, data, *data_len, parsectx) )
		{
			case 0:
				DLOG(MAM_UTIL_NOISY_DEBUG2, "parsing TLV successful\n");
				break;
			default:
				DLOG(MAM_UTIL_NOISY_DEBUG0, "WARNING: parsing TLV failed: tag=%d data_len=%ld\n", (int) *tag, (long) *data_len);
				break;
		}
	}

    evbuffer_drain(ctx->in, tlv_len);
	return(tlv_len);

}


