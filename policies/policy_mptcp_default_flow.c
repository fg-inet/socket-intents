#include "policy_mptcp_default_flow.h"

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

static mam_context_t *global_mctx = NULL;

void print_policy_info(void *policy_info)
{
	struct default_flow_info *info = policy_info;
	if (info->is_enabled_for_flow == 1)
		printf(" (allowing flows)");
	else
		printf(" (NOT allowing flows)");
}

/** Helper to set the policy information for each prefix
 *  Here, check if this prefix has been configured as default
 */
void set_policy_info(gpointer elem, gpointer _mctx)
{
	struct mam_context *mctx = (struct mam_context *) _mctx;
	struct src_prefix_list *spl = elem;

	struct default_flow_info *new = malloc(sizeof(struct default_flow_info));
	memset(new, 0, sizeof(struct default_flow_info));

	if (spl->policy_set_dict != NULL)
	{
		gpointer value = NULL;
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "allowflow")) != NULL)
			new->is_enabled_for_flow = atoi(value);
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value)
		{
            new->is_default = 1;
            g_hash_table_replace(mctx->state, "default-interface", spl->if_addrs->addr);
		}
		else
		{
			new->is_default = 0;
		}
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
				struct in_addr ad = {.s_addr = *(unsigned long*)g_hash_table_lookup(global_mctx->state, "default-interface")};

				strbuf_printf(&sb, "\nspl: %s | default: %s\n", inet_ntoa(((struct sockaddr_in *) spl->if_addrs->addr)->sin_addr), inet_ntoa(ad));

				if  (((ad.s_addr - ((struct sockaddr_in *) rctx->ctx->remote_sa)->sin_addr.s_addr) & ((struct sockaddr_in *) spl->if_netmask)->sin_addr.s_addr) == 0)
				{
					struct sockaddr_in sock = {.sin_family = AF_INET, .sin_port = 0, .sin_addr = ad};

					_set_bind_sa(rctx, (struct sockaddr*) &sock, &sb);
					strbuf_printf(&sb, "\nDEBUG: binding prefix configured default: %s\n", inet_ntoa(ad));
					assigned = 1;
				}
				else
				// try to bind prefix to source that is in the same network as the destination
				if (( ( ((struct sockaddr_in *) spl->if_addrs->addr)->sin_addr.s_addr -
					   ((struct sockaddr_in *) rctx->ctx->remote_sa)->sin_addr.s_addr  ) &
					   ((struct sockaddr_in *) spl->if_netmask)->sin_addr.s_addr) == 0)
				{
					set_bind_sa(rctx, spl, &sb);
					strbuf_printf(&sb, "\nDEBUG: binding prefix to: %s\n", inet_ntoa( ((struct sockaddr_in *) spl->if_addrs->addr)->sin_addr));
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

	g_slist_foreach(mctx->prefixes, &set_policy_info, mctx);
    
	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	printf("\nPolicy module \"default_flow\" has been loaded.\n");

	global_mctx = mctx;

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

void establish_new_flow(gpointer elem, gpointer ip)
{
	struct mptcp_flow_info *flow = (struct mptcp_flow_info*) elem;
	struct sockaddr_storage *ss_ip = (struct sockaddr_storage*) ip;

	if (ss_ip->ss_family == AF_INET)
	{
		struct in_addr in;
		in = ((struct sockaddr_in *)ss_ip)->sin_addr;

		if(((struct sockaddr_in *)&(flow->loc_addr))->sin_addr.s_addr == in.s_addr)
		{
			printf("matching!!! create new v4 flow over: %s\n", inet_ntoa(in));
			printf("flow: loc_addr: %x\n      rem_addr: %x\n      rem_port: %u\n      inode: %x:%x\n      token: %x", 
										(uint32_t)((struct sockaddr_in *)&(flow->loc_addr))->sin_addr.s_addr, 
										(uint32_t)((struct sockaddr_in *)&(flow->rem_addr))->sin_addr.s_addr, 
										flow->rem_port, 
										(uint32_t)(flow->inode >> 32), 
										(uint32_t)(flow->inode & 0xFFFFFFFF), 
										flow->token);

			create_new_flow(flow);
		}
	}
	else
	if (ss_ip->ss_family == AF_INET6)
	{
		struct in6_addr in;
		in = ((struct sockaddr_in6 *)ss_ip)->sin6_addr;

		if(test_if_in6_is_equal(((struct sockaddr_in6 *)&(flow->loc_addr))->sin6_addr, in))
		{
			char straddr[INET6_ADDRSTRLEN];
			char straddr_loc[INET6_ADDRSTRLEN];
			char straddr_rem[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &in, straddr, sizeof(straddr));
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&(flow->loc_addr))->sin6_addr), straddr_loc, sizeof(straddr_loc));
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&(flow->rem_addr))->sin6_addr), straddr_rem, sizeof(straddr_rem));


			printf("matching!!! create new v6 flow over: %s\n", straddr);

			printf("flow: loc_addr: %s\n      rem_addr: %s\n      rem_port: %u\n      inode: %x:%x\n      token: %x", 
										straddr_loc, 
										straddr_rem, 
										flow->rem_port, 
										(uint32_t)(flow->inode >> 32), 
										(uint32_t)(flow->inode & 0xFFFFFFFF), 
										flow->token);

			create_new_flow(flow);
		}
	}
	else
	{
		perror("family of new subflow is not set!\n");
	}
}

void __g_slist_foreach(gpointer key, gpointer value, gpointer user) {
	g_slist_foreach(value, &establish_new_flow, user);
}

void __g_hash_table_foreach(gpointer elem, gpointer ip) {
	g_hash_table_foreach((GHashTable*)((client_list_t*)elem)->flow_table, &__g_slist_foreach, ip);
}

int on_config_request(mam_context_t *mctx, char* config)
{
	struct sockaddr_storage *ip;
	ip = malloc(sizeof(struct sockaddr_storage));

	printf("on_config got called from mptcp default flow policy\n");

	if (inet_pton(AF_INET, config, &((struct sockaddr_in *)ip)->sin_addr))
		ip->ss_family = AF_INET;
	else
	if (inet_pton(AF_INET6, config, &((struct sockaddr_in6 *)ip)->sin6_addr))
		ip->ss_family = AF_INET6;
	else
	{
		printf("could not parse new config data - ignoring\n");
		free(ip);
		return -1;
	}

	g_hash_table_replace(mctx->state, "default-interface", ip);
	printf("new default: %s\n", config);
	g_slist_foreach(global_mctx->clients, &__g_hash_table_foreach, ip);

	return 0;
}

gint compare_inode_in_struct(gpointer list_data,  gpointer user_data)
{
	client_list_t *list = (client_list_t*) list_data;
	uint64_t *inode = (uint64_t*) user_data;
	
	printf("client: %u:%u | compare: %u:%u\n", (uint32_t)((list->inode) >> 32),
 										   		(uint32_t)((list->inode) & 0xFFFFFFFF),
												(uint32_t)((*inode) >> 32),
 										   		(uint32_t)((*inode) & 0xFFFFFFFF));

	if (list->inode == *inode)
		return 0;
	
	return -1;
}

int on_new_subflow_request(mam_context_t *mctx, struct mptcp_flow_info *flow)
{
	printf("\nPolicy function: \"on_new_subflow_request\" is called.\n");

	if ((uint32_t)((struct sockaddr_in *)&(flow->loc_addr))->sin_addr.s_addr == (*(unsigned long*)(g_hash_table_lookup(mctx->state, "default-interface"))))
	{
		printf("establishing subflow!\n");
		return 1;	
	}
	else
	{
		GSList *client_list = g_slist_find_custom(global_mctx->clients, &flow->inode, (GCompareFunc)compare_inode_in_struct);

		if (flow->loc_addr.ss_family == AF_INET)
			printf("Adding new v4 flow to candiats: loc: %x, rem: %X\n", ((struct sockaddr_in *)&(flow->loc_addr))->sin_addr.s_addr, ((struct sockaddr_in *)&(flow->rem_addr))->sin_addr.s_addr);
		else
		{
			char straddr_loc[INET6_ADDRSTRLEN];
			char straddr_rem[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&(flow->loc_addr))->sin6_addr), straddr_loc, sizeof(straddr_loc));
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&(flow->rem_addr))->sin6_addr), straddr_rem, sizeof(straddr_rem));

			printf("Adding new v6 flow to candidats: loc: %s, rem: %s\n", straddr_loc, straddr_rem);
		}

		if (client_list)
		{
			struct mptcp_flow_info *new_flow;
			GSList *flow_table_entry;
			GHashTable *flow_hash = (GHashTable*)((client_list_t*)client_list->data)->flow_table;

			new_flow = malloc(sizeof(struct mptcp_flow_info));

			memcpy(&new_flow->loc_addr, &flow->loc_addr, sizeof(struct sockaddr_storage));
			memcpy(&new_flow->rem_addr, &flow->rem_addr, sizeof(struct sockaddr_storage));
			new_flow->loc_id = flow->loc_id;
			new_flow->rem_id = flow->rem_id;
			new_flow->loc_low_prio = flow->loc_low_prio;
			new_flow->rem_low_prio = flow->rem_low_prio;
			new_flow->rem_bitfield = flow->rem_bitfield;
			new_flow->rem_port = flow->rem_port;
			new_flow->inode = flow->inode;
			new_flow->token = flow->token;

			flow_table_entry = g_hash_table_lookup(flow_hash, GINT_TO_POINTER(flow->token));
			flow_table_entry = g_slist_append(flow_table_entry, new_flow);
			g_hash_table_replace(flow_hash, GINT_TO_POINTER(flow->token), flow_table_entry);
		}
		else
			printf("COULD NOT FIND CLIENT\n");
	
	}
	return 0;
}