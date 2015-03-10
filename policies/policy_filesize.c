/** \file policy_filesize.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "policy.h"
#include "policy_util.h"

/* Per-prefix info about filesize range */
struct filesize_info {
	int 		minfilesize;
	int			maxfilesize;
	int			is_default;
};

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

char addr_str[INET6_ADDRSTRLEN];	/** string for debug / error printing */

void print_policy_info(void *policy_info)
{
	struct filesize_info *info = policy_info;
	printf("\t(for filesize %6d =< n =< %6d)", info->minfilesize, info->maxfilesize);
	if (info->is_default)
		printf(" (default)");
}

void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct filesize_info *new = malloc(sizeof(struct filesize_info));
	memset(new, 0, sizeof(struct filesize_info));
	new->maxfilesize = INT_MAX;

	if (spl->policy_set_dict != NULL)
	{
		/* Set filesize from config file */
		gpointer value = NULL;
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "minfilesize")) != NULL)
			new->minfilesize = atoi(value);
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "maxfilesize")) != NULL)
			new->maxfilesize = atoi(value);
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value)
            new->is_default = 1;
	}

	spl->policy_info = (void *) new;
}

void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if(spl->policy_info != NULL)
		free(spl->policy_info);
}

static void set_sa_for_filesize(request_context_t *rctx, int filesize, strbuf_t sb)
{
	GSList *elem = NULL;
	struct src_prefix_list *spl = NULL;
	struct src_prefix_list *defaultaddr = NULL;

	if (rctx->ctx->domain == AF_INET)
		elem = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		elem = in6_enabled;

	while (elem != NULL)
	{
		spl = elem->data;
		struct filesize_info *info = spl->policy_info;

		if (info->minfilesize <= filesize && info->maxfilesize >= filesize)
		{
			/* Filesizes falls within this prefixes' configuration: Set source address */
			set_bind_sa(rctx, spl, &sb);
			strbuf_printf(&sb, " for filesize %d", filesize);
			break;
		}
		if (info->is_default)
		{
			/* This prefix is default. Store it for eventual fallback. */
			defaultaddr = spl;
		}
		elem = elem->next;
	}

	if (elem == NULL)
	{
		if (filesize > 0)
			strbuf_printf(&sb, "\n\tCould not find suitable address for filesize %d", filesize);
		if (defaultaddr != NULL)
		{
			set_bind_sa(rctx, defaultaddr, &sb);
			strbuf_printf(&sb, " (default)");
		}
	}
}

int init(mam_context_t *mctx)
{
	printf("\nPolicy module \"filesize\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	printf("\nPolicy module \"filesize\" has been loaded.\n");

	return 0;
}

int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);
	printf("\nPolicy module \"filesize\" cleaned up.\n");
	return 0;
}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("\tResolve request: Not resolving\n\n");
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	int fs = 0;
	socklen_t fslen = sizeof(int);
	if (mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_FILESIZE, &fslen, &fs) != 0)
	{
		// no filesize given - Setting default address
		strbuf_printf(&sb, "\n\tNo filesize intent given - Using default if applicable.");
		set_sa_for_filesize(rctx, -1, sb);
	}
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\t\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}

	else
	{
		set_sa_for_filesize(rctx, fs, sb);
	}

	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}
