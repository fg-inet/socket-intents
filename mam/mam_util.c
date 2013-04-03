#include <stdio.h>
#include <stdlib.h>
#include <ltdl.h>

#include "mam.h"
#include "../clib/muacc_util.h"

size_t _mam_print_sockaddr_list(char *buf, size_t *buf_pos, size_t buf_len, const struct sockaddr_list *list)
{
	size_t old_pos = *buf_pos;
	const struct sockaddr_list *current = list;

	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "{ ");

	while (current != NULL)
	{
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "{ ");
		_muacc_print_sockaddr(buf, buf_pos, buf_len, current->addr, current->addr_len);
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
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "{ ");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "if_name = %s, ", current->if_name);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "if_flags = %d, ", current->if_flags);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos), "if_addrs = ");
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
	if (ctx == NULL)
	{
		return -1;
	}

	struct src_prefix_list *curitem = NULL;
	struct sockaddr_list *current = NULL;
	while (ctx->prefixes != NULL)
	{
		curitem = ctx->prefixes;
		if (curitem->if_name != NULL)		free(curitem->if_name);
		while (curitem->if_addrs != NULL)
		{
			current = curitem->if_addrs;
			if (current != NULL)	free(current);
			curitem->if_addrs = current->next;
			free(current);
		}
		if (curitem->if_netmask != NULL)	free(curitem->if_netmask);
		ctx->prefixes = curitem->next;
		free(curitem);
	}

	free(ctx);

	return 0;
}
