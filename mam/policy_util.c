#include <stdio.h>
#include <string.h>

#include "mam.h"
#include "../clib/muacc_util.h"

int mampol_get_socketopt(struct socketopt *list, int level, int optname, socklen_t *optlen, void *optval)
{
	struct socketopt *current = list;
	int ret = -1;

	while (current != NULL)
	{
		if (current->level == level && current->optname == optname)
		{
			if (current->optval != NULL && optval != NULL)
			{
				*optlen = current->optlen;
				memcpy(optval, current->optval, current->optlen);
			}
			ret = 0;
		}
		current = current->next;
	}
	return ret;
}

int mampol_get_prefix_by_name(struct src_prefix_list *list, const char *name, int family, struct src_prefix_list **pref)
{
	struct src_prefix_list *current = list;

	if (name == NULL)
	{
		fprintf(stderr, "WARNING: Supplied NULL name to mampol_get_prefix_by_name\n");
		return -1;
	}

	while (current != NULL)
	{
		if (0 == strcmp(current->if_name, name) && current->family == family)
		{
			// found
			*pref = current;
			return 0;
		}
		current = current->next;
	}
	return -1;
}

int mampol_suggest_bind_sa(request_context_t *rctx, const char *name)
{
	struct src_prefix_list *preferred = NULL;

	if (name == NULL)
	{
		fprintf(stderr, "WARNING: Supplied NULL name to mampol_suggest_bind_sa\n");
		return -1;
	}

	if (0 == mampol_get_prefix_by_name(rctx->mctx->prefixes, name, rctx->ctx->domain, &preferred))
	{
		rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(preferred->if_addrs->addr, preferred->if_addrs->addr_len);
		rctx->ctx->bind_sa_suggested_len = preferred->if_addrs->addr_len;
		return 0;
	}
	return -1;
}
