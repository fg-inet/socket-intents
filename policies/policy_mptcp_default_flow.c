#include "policy.h"
#include "policy_util.h"
#include "../lib/muacc.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../mam/mptcp_netlink_parser.h"

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;



/** Policy-specific per-prefix data structure that contains additional information */
struct default_flow_info {
	int is_enabled_for_flow;
	int is_default;
};

void print_policy_info(void *policy_info)
{
	struct default_flow_info *info = policy_info;
	if (info->is_enabled_for_flow == 1)
		printf(" (flow enabled)");
}


struct mptcp_session {
	muacc_ctxino_t inode;
	int is_default_src;
};


/** Helper to set the policy information for each prefix
 *  Here, check if this prefix has been configured as default
 */
void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct default_flow_info *new = malloc(sizeof(struct default_flow_info));
	memset(new, 0, sizeof(struct default_flow_info));

	if (spl->policy_set_dict != NULL)
	{
		gpointer value = NULL;
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "flow")) != NULL)
			new->is_enabled_for_flow = atoi(value);
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value)
            new->is_default = 1;
	}
	spl->policy_info = (void *) new;
}


static void set_sa(request_context_t *rctx, strbuf_t sb, int do_not_bind)
{
	GSList *elem = NULL;
	struct src_prefix_list *spl = NULL;
	struct src_prefix_list *defaultaddr = NULL;
	struct default_flow_info *info = NULL;
    int assigned = 0;
	
	//struct sockaddr_in *sin;
	//char straddr[INET6_ADDRSTRLEN];
	
	strbuf_printf(&sb, "\nDEBUG: set_sa called\n");

	if (rctx->ctx->domain == AF_INET)
		elem = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		elem = in6_enabled;

	while (elem != NULL)
	{
		spl = elem->data;
		info = (struct default_flow_info *)spl->policy_info;

		if (!assigned)
		{
			if (!do_not_bind)
			{
				// try to bind prefix to source that is in the same network as the destination
				if (!( ( ((struct sockaddr_in *) spl->if_addrs->addr)->sin_addr.s_addr -
					   ((struct sockaddr_in *) rctx->ctx->remote_sa)->sin_addr.s_addr  ) &
					   ((struct sockaddr_in *) spl->if_netmask)->sin_addr.s_addr) )
				{
					set_bind_sa(rctx, spl, &sb);
					strbuf_printf(&sb, "\nDEBUG: binding prefix ...");
					assigned = 1;
				}
			}
		}
		
		//set_ignore_prefix(spl->if_addrs->addr, rctx->ctx->ctxino);
		
		if (info->is_default)
		{
			/* This prefix is default. Store it for eventual fallback. */
			defaultaddr = spl;
		}
		
		elem = elem->next;
	}

	// if no source is in the same network as the destination, use the default interface
	if (!assigned)
	{
		if (defaultaddr != NULL)
		{
			set_bind_sa(rctx, defaultaddr, &sb);
			strbuf_printf(&sb, " (default)");
		}
	}
}

int init(mam_context_t *mctx)
{
	printf("\nPolicy module \"default_flow\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);
    
	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	printf("\nPolicy module \"default_flow\" has been loaded.\n");

	return 0;
}

void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if(spl->policy_info != NULL)
		free(spl->policy_info);
}

int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);
	printf("\nPolicy module \"default_flow\" cleaned up.\n");
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

	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\t\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		
	}
	set_sa(rctx, sb, (rctx->ctx->bind_sa_req)?1:0);

	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}


int on_new_subflow_request(mam_context_t *mctx, struct mptcp_flow_info *flow)
{
	printf("\nPolicy function: \"on_new_subflow_request\" is called.\n");
	
	GSList *elem = in4_enabled;
	struct src_prefix_list *spl = NULL;
	
	while (elem != NULL)
	{
		spl = elem->data;
		struct default_flow_info *info = spl->policy_info;
		
		printf("address from list : %X", ((struct sockaddr_in *) spl->if_addrs->addr)->sin_addr.s_addr);
		
		printf(" flow : %X is enabled?: %d\n", flow->loc_addr, info->is_enabled_for_flow);
		
		if (((struct sockaddr_in *) spl->if_addrs->addr)->sin_addr.s_addr == flow->loc_addr &&
			info->is_enabled_for_flow == 1)
		{
			printf("establishing subflow!\n");
			return 1;
		}
		
		elem = elem->next;
	}
	return 0;
}