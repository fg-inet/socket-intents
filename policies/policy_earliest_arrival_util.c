/** \file policy_earliest_arrival_util.c
 *  \brief Helper functions for earliest arrival policy
 *
 *  \copyright Copyright 2013-2016 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "policy_earliest_arrival.h"

/** Returns the default prefix, if any exists, otherwise NULL
 */
struct src_prefix_list *get_default_prefix(request_context_t *rctx, GSList *in4_enabled, GSList *in6_enabled, strbuf_t *sb)
{
	GSList *spl = NULL;
	struct src_prefix_list *cur = NULL;
	struct eafirst_info *info = NULL;

	// If address family is specified, only look in its list, else look in both (v4 first)
	if (rctx->ctx->domain == AF_INET)
		spl = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		spl = in6_enabled;
	else
		spl = g_slist_concat(in4_enabled, in6_enabled);

	// Go through list of src prefixes
	while (spl != NULL)
	{
		// Look at per-prefix policy information
		cur = spl->data;
		info = (struct eafirst_info *)cur->policy_info;
		if (info != NULL && info->is_default)
		{
			// This prefix is configured as default. Return it
			strbuf_printf(sb, "\tFound default prefix ");
	        _muacc_print_sockaddr(sb, cur->if_addrs->addr, cur->if_addrs->addr_len);
			strbuf_printf(sb, "\n");
			return cur;
		}
		spl = spl->next;
	}
	strbuf_printf(sb, "\tDid not find a default prefix %s%s\n", (rctx->ctx->domain == AF_INET) ? "for IPv4" : "", (rctx->ctx->domain == AF_INET6) ? "for IPv6" : "");

	return NULL;
}
