#include "policy_mptcp_default_flow.h"

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

static mam_context_t *global_mctx = NULL;

struct src_prefix_list *get_default_prefix(request_context_t *rctx, strbuf_t *sb);

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

struct src_prefix_list *get_default_prefix(request_context_t *rctx, strbuf_t *sb)
{
	GSList *spl = NULL;
	struct src_prefix_list *cur = NULL;
	struct default_flow_info *info = NULL;

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
		info = (struct default_flow_info *)cur->policy_info;
		if (info != NULL && info->is_default)
		{
			/* This prefix is configured as default. Return it */
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

static void resolve_request_result(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	request_context_t *rctx = ptr;

	strbuf_t sb;
	strbuf_init(&sb);

	if (errcode) {
	    strbuf_printf(&sb, "\t[%.6f] Error resolving: %s -> %s\n", gettimestamp(), rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
		rctx->action = muacc_error_resolve;
	}
	else
	{
		// Successfully resolved name
		strbuf_printf(&sb, "\t[%.6f] Got resolver response for %s %s\n",
			gettimestamp(),
			rctx->ctx->remote_hostname,
			addr->ai_canonname ? addr->ai_canonname : "");

		strbuf_printf(&sb, "\t");
		_muacc_print_addrinfo(&sb, addr);
		strbuf_printf(&sb, "\n");

		// Clone result into the request context
		assert(addr != NULL);
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(addr);

		// Choose first result as the remote address
		rctx->ctx->domain = addr->ai_family;
		rctx->ctx->type = addr->ai_socktype;
		rctx->ctx->protocol = addr->ai_protocol;
		rctx->ctx->remote_sa_len = addr->ai_addrlen;
		rctx->ctx->remote_sa = _muacc_clone_sockaddr(addr->ai_addr, addr->ai_addrlen);

		// Print remote address
		strbuf_printf(&sb, "\n\tSet remote address =");
		_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);
		strbuf_printf(&sb, "\n");

        //strbuf_release(&sb);
		evutil_freeaddrinfo(addr);
	}

	// send reply to client
	strbuf_printf(&sb, "\n\t[%.6f] Sending reply\n", gettimestamp());
	_muacc_send_ctx_event(rctx, rctx->action);

    printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);
    printf("\n\t[%.6f] Returning resolve result callback\n\n", gettimestamp());
}


int resolve_name(request_context_t *rctx)
{
	strbuf_t sb;
	strbuf_init(&sb);

	struct evdns_base *evdns_base = rctx->evdns_base;

	// If no dns base is given for the chosen source prefix, use default dns base
	if (evdns_base == NULL) {
		strbuf_printf(&sb, "\tNo prefix-specific DNS base found - using default DNS base\n");
		evdns_base = rctx->mctx->evdns_default_base;
	}

	// Set hints to resolve name for our chosen address family
	if (rctx->ctx->remote_addrinfo_hint != NULL) {
		rctx->ctx->remote_addrinfo_hint->ai_family = rctx->ctx->domain;
	}
	else
	{
		// Initialize hints for address resolution
		rctx->ctx->remote_addrinfo_hint = malloc(sizeof(struct addrinfo));
		memset(rctx->ctx->remote_addrinfo_hint, 0, sizeof(struct addrinfo));
		rctx->ctx->remote_addrinfo_hint->ai_family = rctx->ctx->domain;
		rctx->ctx->remote_addrinfo_hint->ai_socktype = rctx->ctx->type;
		rctx->ctx->remote_addrinfo_hint->ai_protocol = rctx->ctx->protocol;
	}

	if (evdns_base_set_option(evdns_base, "timeout", "1") < 0)
	{
		strbuf_printf(&sb, "Setting DNS timeout failed\n");
	}

	strbuf_printf(&sb, "\t[%.6f] Resolving: %s:%s with hint: ", gettimestamp(), (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	_muacc_print_addrinfo(&sb, rctx->ctx->remote_addrinfo_hint);
	strbuf_printf(&sb, "\n");

	/* Try to resolve this request using asynchronous lookup */
	assert(evdns_base != NULL);
	evdns_getaddrinfo(
			evdns_base,
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
			rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result,
			rctx);

	printf("%s\n", strbuf_export(&sb));
	strbuf_release(&sb);

	printf("\t[%.6f] Returning resolve_name.\n\n", gettimestamp());
	return 0;
}


int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("\n\t[%.6f] Resolve request: %s:%s\n\n", gettimestamp(), (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		printf("\tBind interface already specified\n");
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;

		struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
		if (bind_pfx != NULL) {
			// Set DNS base to this prefix's
			rctx->evdns_base = bind_pfx->evdns_base;
			printf("\tSet DNS base\n");
		}
	}

	rctx->action = muacc_act_getaddrinfo_resolve_resp;

	printf("\n\t[%.6f] Calling resolve_name\n", gettimestamp());
	return resolve_name(rctx);
}


int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\t[%.6f] Connect request: dest=", gettimestamp());
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	// Check if client has already chosen a source address to bind to
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;
	}
	else
	{
		// search default address, and set it as bind_sa in the request context if found
		struct src_prefix_list *bind_pfx = get_default_prefix(rctx, &sb);
		if (bind_pfx != NULL) {
			set_bind_sa(rctx, bind_pfx, &sb);
		}
	}

    // Add MPTCP option to sockopts_suggested, so it will be set on the new socket
    int enabled = 1;
    _muacc_add_sockopt_to_list(&(rctx->ctx->sockopts_suggested), SOL_TCP, 42, &enabled, sizeof(enabled), 0);

	// send response back
	strbuf_printf(&sb, "\n\t[%.6f] Sending reply\n", gettimestamp());
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);

    printf("%s\n", strbuf_export(&sb));
    strbuf_release(&sb);

	printf("\t[%.6f] Returning\n\n", gettimestamp());
	return 0;
}

int on_socketconnect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);

	printf("\n\tSocketconnect request: %s:%s\n\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	double timestamp = gettimestamp();

	// Check if client has already chosen a source address to bind to
	if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
		rctx->ctx->domain = rctx->ctx->bind_sa_req->sa_family;
		struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
		if (bind_pfx != NULL) {
			// Set DNS base to this prefix's
			rctx->evdns_base = bind_pfx->evdns_base;
			strbuf_printf(&sb, ", set DNS base. ");
		}
	}
	else
	{
		// search default address, and set it as bind_sa in the request context if found
		struct src_prefix_list *bind_pfx = get_default_prefix(rctx, &sb);
		if (bind_pfx != NULL) {
			set_bind_sa(rctx, bind_pfx, &sb);

			// Set this prefix' evdns base for name resolution
			rctx->evdns_base = bind_pfx->evdns_base;
		}
		else
		{
			rctx->evdns_base = NULL;
		}
	}

    // Add MPTCP option to sockopts_suggested, so it will be set on the new socket
    int enabled = 1;
    _muacc_add_sockopt_to_list(&(rctx->ctx->sockopts_suggested), SOL_TCP, 42, &enabled, sizeof(enabled), 0);


    printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);

	rctx->action = muacc_act_socketconnect_resp;

	return resolve_name(rctx);
}

int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);

	printf("\n\tSocketchoose request: %s:%s\n\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
	double timestamp = gettimestamp();
    char *logfile = NULL;
	GSList *spl = in4_enabled;
	while (spl != NULL)
	{
        struct src_prefix_list *cur = spl->data;
		int reuse = count_sockets_on_prefix(rctx->sockets, cur, logfile);
		spl = spl->next;
	}

	// Check if a set of existing sockets was supplied in the request
	if (rctx->sockets != NULL)
	{
		// First socket of set will be chosen
		printf("\tSuggest using socket %d\n", rctx->sockets->file);

		/* Provide the information to open a new similar socket, in case the suggested socket cannot be used */
		uuid_t context_id;
		__uuid_copy(context_id, rctx->ctx->ctxid);
		rctx->ctx = _muacc_clone_ctx(rctx->sockets->ctx);
		__uuid_copy(rctx->ctx->ctxid, context_id);

		strbuf_printf(&sb, "\n\tSending reply\n");
		_muacc_send_ctx_event(rctx, muacc_act_socketchoose_resp_existing);

		printf("%s\n\n", strbuf_export(&sb));
		strbuf_release(&sb);

		return 0;
	}
	else
	{
		printf("\tSocketchoose with empty set - trying to create new socket\n");

		if(rctx->ctx->bind_sa_req != NULL)
		{	// already bound
			strbuf_printf(&sb, "\tAlready bound to src=");
			_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);

			struct src_prefix_list *bind_pfx = get_pfx_with_addr(rctx, rctx->ctx->bind_sa_req);
			if (bind_pfx != NULL) {
				// Set DNS base to this prefix's
				rctx->evdns_base = bind_pfx->evdns_base;
				strbuf_printf(&sb, ", set DNS base. ");
			}
		}
		else
		{
			// search default address, and set it as bind_sa in the request context if found
			struct src_prefix_list *bind_pfx = get_default_prefix(rctx, &sb);
			if (bind_pfx != NULL) {
				set_bind_sa(rctx, bind_pfx, &sb);

				// Set this prefix' evdns base for name resolution
				rctx->evdns_base = bind_pfx->evdns_base;
				strbuf_printf(&sb, ", set DNS base. ");
			}
			else
			{
				rctx->evdns_base = NULL;
			}
		}

		printf("%s\n\n", strbuf_export(&sb));
		strbuf_release(&sb);

		rctx->action = muacc_act_socketchoose_resp_new;

		return resolve_name(rctx);
	}
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
