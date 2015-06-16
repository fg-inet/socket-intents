/** \file policy_gpac.c
 *  \brief Example policy to illustrate how gpac works with the MUACC framework
 *
 *  \copyright Copyright 2013-2015 Patrick Kutter, Philipp Schmidt and Theresa Enghardt.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  Policy_info: Whether interface has been specified as default in the config file
 *               (e.g. set default = 1 in the prefix statement)
 *  Behavior:
 *  Getaddrinfo - Resolve names using the default dns_base from the MAM context
 *  Connect     - Choose the default interface if available
 */
//based on policy_sample.c

#include "policy.h"
#include "policy_util.h"

#ifndef DEBUG_OUTPUT_0
#define DEBUG_OUTPUT_0 0
#endif

/** Policy-specific per-prefix data structure that contains additional information */
//struct sample_info {
//	int is_default;
//};

struct intents_info {
    int minfilesize;
    int maxfilesize;
	enum intent_category	category;
	char					*category_string;
	int						is_default;
};

/** List of enabled addresses for each address family */
GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

/** declaration of helper functions */
typedef struct socketlist socketlist;
typedef struct src_prefix_list src_prefix_list;
void set_sa(request_context_t *rctx, enum intent_category given, int filesize, strbuf_t *sb);
struct src_prefix_list* map_sock_to_src_prefix(request_context_t *rctx, struct socketlist *given_socket);
int check_socket_for_intent(request_context_t *rctx, socketlist *given_socket);


/** Helper to set the policy information for each prefix
 *  Here, check if this prefix has been configured as default
 *  and parse the category information from config file
 */
void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct intents_info *new = malloc(sizeof(struct intents_info));
	new->is_default = 0;

	if (spl->policy_set_dict != NULL)
	{
		gpointer value = NULL;

		// parse the config file for arguments
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "category")) != NULL)
		{
			enum intent_category cat = -1;
			if (strcmp(value, "bulktransfer") == 0)
				cat = INTENT_BULKTRANSFER;
			else if (strcmp(value, "query") == 0)
				cat = INTENT_QUERY;
			else if (strcmp(value, "controltraffic") == 0)
				cat = INTENT_CONTROLTRAFFIC;
			else if (strcmp(value, "keepalives") == 0)
				cat = INTENT_KEEPALIVES;
			else if (strcmp(value, "stream") == 0)
				cat = INTENT_STREAM;
			else
				printf("WARNING: Cannot set invalid category %s\n", (char *)value);

			if (cat >= 0 && cat <= INTENT_STREAM)
			{
				/* found valid category in config file */
				new->category = cat;
				asprintf(&(new->category_string), "%s", (char *) value);
			}
		}
		// check for filesize restrictions on this interface, in none found minsize =-1 and maxsize = -1
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "minfilesize")) != NULL)
            new->minfilesize= atoi(value);
            else
                new->minfilesize = -1;
        if ((value = g_hash_table_lookup(spl->policy_set_dict, "maxfilesize")) != NULL)
            new->maxfilesize= atoi(value);
            else
                new->maxfilesize=-1;
		// set default interface
		if ((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL)
			new->is_default = 1;
	}
	spl->policy_info = new;
}

/** Helper to print additional information given to the policy
 */
void print_policy_info(void *policy_info)
{
	struct intents_info *info = policy_info;
	if (info->is_default)
		printf("\n\t policy contains default interface");
    if (info->category_string)
        printf(" \n\t policy information for category: %s ", info->category_string);
    if (info->maxfilesize)
        printf("\n\t maximumfilesize info: %i", info->maxfilesize);
    if (info->minfilesize)
        printf("\n\t minfilesize info: %i \n", info->minfilesize);
}

/** Free the policy data structures */
void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if (spl->policy_info != NULL)
            free(spl->policy_info);
    spl->policy_info = NULL;
}


//map a given socket to his source prefix
struct src_prefix_list* map_sock_to_src_prefix(request_context_t *rctx, struct socketlist *given_socket)
{
    GSList *spl = NULL;
    int given_domain = given_socket->ctx->domain;
    if(DEBUG_OUTPUT_0){printf(" \n\t domain in given socket: %d ", given_domain);}

	if (given_domain == AF_INET)
		spl = in4_enabled;
	else if (given_domain == AF_INET6)
		spl = in6_enabled;

    //struct intents_info info_curr = prefix_curr->policy_info;
	struct sockaddr *socket_sa_curr = given_socket->ctx->bind_sa_suggested;

    //lookup_source_prefix(spl, 0, NULL, ,)
    struct src_prefix_list *prefix_curr = NULL;

	//check to what source prefix socket_sa_curr belongs

    while(spl != NULL)
    {
        prefix_curr = spl->data;
        struct sockaddr_list *sock_list_for_curr_prefix = prefix_curr->if_addrs;

        while(sock_list_for_curr_prefix != NULL)
        {
            struct sockaddr *sockaddr_prefix = sock_list_for_curr_prefix->addr;
            int equality = -1;
            if (given_domain == AF_INET){
                struct sockaddr_in *ip4_prefix = (struct sockaddr_in *) sockaddr_prefix;
                struct sockaddr_in *ip4_socket = (struct sockaddr_in *) socket_sa_curr;
                char* ip4_pref_char = inet_ntoa(ip4_prefix->sin_addr);
                char* ip4_sock_char = inet_ntoa(ip4_socket->sin_addr);

                if(DEBUG_OUTPUT_0){
                printf("\n\t IP for current interface: %s", ip4_pref_char);
                printf("\n\t IP for given socket: %s", ip4_sock_char);
                }

                struct in_addr *a = &(ip4_prefix->sin_addr);
                struct in_addr *b = &(ip4_socket->sin_addr);
                in_addr_t a_addr = a->s_addr;
                in_addr_t b_addr = b->s_addr;
                equality = b_addr - a_addr;
            }
            if (given_domain == AF_INET6){
                struct sockaddr_in6 *ip6_prefix = (struct sockaddr_in6 *) sockaddr_prefix;
                struct sockaddr_in6 *ip6_socket = (struct sockaddr_in6 *) socket_sa_curr;
                struct in6_addr *a = &(ip6_prefix->sin6_addr);
                struct in6_addr *b = &(ip6_socket->sin6_addr);
                /*a_addr = a->__u6_addr8;
                s6_addr b_addr = b->__u6_addr8;*/

                for(int i=0; i<16; i++)
                {
                    if(0 != (a->s6_addr[i] ^ b->s6_addr[i])){
                        equality = (i+1);
                        if(DEBUG_OUTPUT_0){printf("IPv6 address of interface and current socket are not equal");}
                        break;
                    }
                    else
                        equality = 0;
                }

            }

            if(0 == equality){
                if(DEBUG_OUTPUT_0){printf("\n\t equality of sock and interface IPs: %d ", equality);}
                return prefix_curr;
            }
            sock_list_for_curr_prefix = sock_list_for_curr_prefix->next;
        }

        spl = spl->next;
    }
    return NULL;
}


// helper function to check if a socket ctx, or repectively the corresponding prefix is suited for a given Intent
int check_socket_for_intent(request_context_t *rctx, socketlist *given_socket)
{
    //int check_prefix(src_prefix_list *prefix, sockaddr *addr);
    struct intents_info *prefix_info = NULL;

    intent_category_t request_category = -1;
    int request_filesize = -1;

	socklen_t cat_length = sizeof(intent_category_t);
	socklen_t filesize_length = sizeof(int);

	struct socketopt *request_optlist = rctx->ctx->sockopts_current;

		if (0 != mampol_get_socketopt(request_optlist, SOL_INTENTS, INTENT_CATEGORY, &cat_length, &request_category))
        {
		// no category given
            if(DEBUG_OUTPUT_0)printf("\n\t found no category in request context");
        }
        if (0 != mampol_get_socketopt(request_optlist, SOL_INTENTS, INTENT_FILESIZE, &filesize_length, &request_filesize))
        {
        // no filesize intents given
            if(DEBUG_OUTPUT_0)printf("\n\t found no filesize Intent in request context");
        }

    src_prefix_list *prefix_for_curr_sock = NULL;
    prefix_for_curr_sock = map_sock_to_src_prefix(rctx, given_socket);
	// try to map the current socket to an interface
	if( prefix_for_curr_sock == NULL)
    {
        printf("\t \n could not match prefix for current socket");
        return -1;
    }

    prefix_info = (struct intents_info*) prefix_for_curr_sock->policy_info;

    if(prefix_info != NULL)
    {
                if (prefix_info->category == request_category && (prefix_info->minfilesize) <= request_filesize && request_filesize <= (prefix_info->maxfilesize))
                {
                    if(DEBUG_OUTPUT_0)printf("\n \t Socket suits current request's Intents");
                    return 0;
                }
    }
    else
        printf("\n \t current prefix has no infos attached");

    return -1;
}


/* Set the matching source address for a given category and/or filesize */
void set_sa(request_context_t *rctx, enum intent_category given, int filesize, strbuf_t *sb)
{
	GSList *spl = NULL;
	struct src_prefix_list *cur = NULL;
	struct intents_info *info = NULL;
	struct src_prefix_list *defaultaddr = NULL;

	if(DEBUG_OUTPUT_0)strbuf_printf(sb, "\n \t set_sa() called");

	if (rctx->ctx->domain == AF_INET)
		spl = in4_enabled;
	else if (rctx->ctx->domain == AF_INET6)
		spl = in6_enabled;

	while (spl != NULL)
	{
		cur = spl->data;
		info = (struct intents_info *)cur->policy_info;
		//if no minfilesize is set in config it is set to 0
		if( info != NULL)
        {
            // if filesize, category and policy infos are set
            if(filesize >= 0  && info->maxfilesize >= 0 && given >=0){

                if ((info->category == given) && ((info->minfilesize) <= filesize) && (filesize <= (info->maxfilesize))){
                    /* Category and filesize matches. Set source address */
                    set_bind_sa(rctx, cur, sb);
                    strbuf_printf(sb, "\n \t found suitable interface for category: %s (%d) , and given filesize: %d", info->category_string, given, filesize);

                }
            }
            // if maxfilesize is not set in policy
            else if(filesize >=0 && info->maxfilesize <=0 && given >= 0){
                if ((info->category == given) && ((info->minfilesize) <= filesize))
                {
                    /* Category and filesize matches. Set source address */
                    set_bind_sa(rctx, cur, sb);
                    strbuf_printf(sb, "\n \t found suitable interface for category %s (%d)", info->category_string, given);

                }
            }
            // if no filesize intent is given, then only category matters
            else if(filesize <0 && given >= 0){
                if (info->category == given){
                    /* Category and filesize matches. Set source address */
                    set_bind_sa(rctx, cur, sb);
                    strbuf_printf(sb, "\n \t found suitable interface for category %s (%d)", info->category_string, given);

                }
            }
            // if no filesize and no category are given then every interface is considered suitable
            else if(filesize < 0 && given < 0 ){
                set_bind_sa(rctx, cur, sb);
                    strbuf_printf(sb, "\n \t taking any interface, as no filesize and category are given");
            }



            if (info->is_default)
            {
                /* Configured as default. Store for fallback */
                strbuf_printf(sb, "\n \t setting this interface address as default");
                defaultaddr = cur;
            }
            spl = spl->next;
        }
	}
	if (rctx->ctx->bind_sa_suggested == NULL)
	{
		/* No suitable address for this category was found */
		if (given >= 0 && given <= INTENT_STREAM)
			strbuf_printf(sb, "\n\tDid not find a suitable src address for category %d", given);
		if (defaultaddr != NULL)
		{
			set_bind_sa(rctx, defaultaddr, sb);
			strbuf_printf(sb, "no suitable address for this category was found using (default)");
		}
	}
}

/** Initializer function (mandatory)
 *  Is called once the policy is loaded and every time it is reloaded
 *  Typically sets the policy_info and initializes the lists of candidate addresses
 */
int init(mam_context_t *mctx)
{
	printf("Policy module \"gpac_test\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	printf("\nPolicy module \"gpac_test\" has been loaded.\n");
	return 0;
}

/** Cleanup function (mandatory)
 *  Is called once the policy is torn down, e.g. if MAM is terminates
 *  Tear down lists of candidate addresses (no deep free) and policy infos
 */
int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);

	printf("Policy \"gpac_test\" library cleaned up.\n");
	return 0;
}


/** Asynchronous callback function for socketconnect request after resolve
 *  Invoked once a response to the resolver query has been received
 *  Sends back a reply to the client with the received answer
 */
static void resolve_request_result_connect(int errcode, struct evutil_addrinfo *addr, void *ptr_to_context)
{
	strbuf_t sb;
	strbuf_init(&sb);
	intent_category_t category = -1;
	int filesize = -1;
	socklen_t cat_length = sizeof(intent_category_t);
	socklen_t filesize_length = sizeof(int);

	request_context_t *rctx = ptr_to_context;

	if (errcode) {
	    printf("\n\t Error resolving: %s -> %s\n", rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
	}
	else
	{
		printf("\n\t Got resolver response for %s: %s\n",
			rctx->ctx->remote_hostname,
			addr->ai_canonname ? addr->ai_canonname : "");

		assert(addr != NULL);
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(addr);
		print_addrinfo_response (rctx->ctx->remote_addrinfo_res);

		// Choose first result as the remote address
		rctx->ctx->domain = addr->ai_family;
		rctx->ctx->type = addr->ai_socktype;
		rctx->ctx->protocol = addr->ai_protocol;
		rctx->ctx->remote_sa_len = addr->ai_addrlen;
		rctx->ctx->remote_sa = _muacc_clone_sockaddr(addr->ai_addr, addr->ai_addrlen);

		// free libevent addrinfo
		evutil_freeaddrinfo(addr);

		// Find local address for destination
		strbuf_printf(&sb, "\tDestination address =");
		_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);
		strbuf_printf(&sb, "\n");

		struct socketopt *optlist = rctx->ctx->sockopts_current;

		if (0 != mampol_get_socketopt(optlist, SOL_INTENTS, INTENT_CATEGORY, &cat_length, &category))
        {
		// no category given
            strbuf_printf(&sb, "\n\tNo category intent given - checking for filesize rules.");
        }
        if (0 != mampol_get_socketopt(optlist, SOL_INTENTS, INTENT_FILESIZE, &filesize_length, &filesize))
        {
        // no filesize intents given
                strbuf_printf(&sb, "\n\t No filesize intent given. ");

        }

		else if(rctx->ctx->bind_sa_req != NULL)
		{	// already bound
			strbuf_printf(&sb, "\tAlready bound to src=");
			_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
			strbuf_printf(&sb, "\n");
		}
        /** call set_sa to set the source address accordingt to given intents and policy configuration
        */
			//strbuf_printf(&sb, "\t \n callin set sa for category ");
			set_sa(rctx, category, filesize, &sb);

			// search address to bind to
			if(rctx->ctx->bind_sa_suggested != NULL)
			{
				strbuf_printf(&sb, "\t \n Suggested source address for given intents, address: ");
				_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_suggested, rctx->ctx->bind_sa_suggested_len);
				strbuf_printf(&sb, "\n");
			}
			else
				strbuf_printf(&sb, "\tNo default interface is available!\n");

	}

	muacc_mam_action_t action = muacc_act_socketconnect_resp;
	// send response back
	if (rctx->action == muacc_act_socketchoose_req)
	{
		action = muacc_act_socketchoose_resp_new;
	}
	_muacc_send_ctx_event(rctx, action);

    printf("%s\n\n", strbuf_export(&sb));
    strbuf_release(&sb);
}

/** Socketconnect request function
 *  Is called upon each socketconnect request from a client
 *  Performs name resolution and then chooses a local address
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketconnect_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;

	printf("\tSocketconnect request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	/* Try to resolve this request using asynchronous lookup */
    req = evdns_getaddrinfo(
    		rctx->mctx->evdns_default_base,
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result_connect,
			rctx);
	printf(" - Sending request to default nameserver\n");
    if (req == NULL) {
		/* returned immediately - Send reply to the client */
		_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
		printf("\tRequest failed.\n");
	}
	return 0;
}

/** Socketchoose request function
 *  Is called upon each socketchoose request from a client
 *  Chooses from a set of existing sockets
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;


    struct socketlist *curr_socket = rctx->sockets;
    struct socketlist *prev_socket = NULL;

	printf("\tSocketchoose request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));
    /*if(DEBUG_OUTPUT_0)printf("\t what domain is given in rctx->ctx: %d", rctx->ctx->domain);
    if(DEBUG_OUTPUT_0)printf("\t  what  domain ins socketlist rctx->sockets->ctx: %d ", rctx->sockets->ctx->domain);*/

    //only select sockets that have same intents as the request itself
    while(curr_socket != NULL)
    {
        // check if current socket fits to request intents and delete it from sockets list if necessary
       if(0 != check_socket_for_intent(rctx, curr_socket))
        {
            if(prev_socket == NULL)
            {
                rctx->sockets = rctx->sockets->next;

            }
            else
            {
                prev_socket->next = curr_socket->next;

            }
            struct socketlist *to_delete = curr_socket;
            curr_socket = curr_socket->next;

            //free the unused socket
            _muacc_free_ctx(to_delete->ctx);
			free(to_delete);

        }
        else
        {
            prev_socket =  curr_socket;
            curr_socket = curr_socket->next;
        }

    }

	if (rctx->sockets != NULL)
	{
		printf("\tSuggest using this socket first %d\n", rctx->sockets->file);

		/* Provide the information to open a new similar socket, in case the suggested socket cannot be used */
		// i.e. copying the current ctxid into the cloned ctx
		uuid_t context_id;
		__uuid_copy(context_id, rctx->ctx->ctxid);
		rctx->ctx = _muacc_clone_ctx(rctx->sockets->ctx);
		__uuid_copy(rctx->ctx->ctxid, context_id);

		_muacc_send_ctx_event(rctx, muacc_act_socketchoose_resp_existing);
	}
	else if(rctx->sockets == NULL)
	{
		printf("\tSocketchoose with empty set - trying to create new socket, resolving %s:%s\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

		/* Try to resolve this request using asynchronous lookup */
		req = evdns_getaddrinfo(
    		rctx->mctx->evdns_default_base,
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result_connect,
			rctx);
		printf(" - Sending request to default nameserver\n");
		if (req == NULL) {
			/* returned immediately - Send reply to the client */
			_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
			printf("\tRequest failed.\n");
		}
	}

	return 0;
}
