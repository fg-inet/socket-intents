/** \file policy_rr_pipelining.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "policy.h"
#include "policy_util.h"
#include "clib/muacc_client_util.h"

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;
int lastsocket = 0;

char addr_str[INET6_ADDRSTRLEN];	/** string for debug / error printing */

void set_sa_rr (request_context_t *rctx, strbuf_t sb);

/** Setting source address: Choose the next address from the circular list */
void set_sa_rr (request_context_t *rctx, strbuf_t sb)
{
	if(rctx->ctx->domain == AF_INET && in4_enabled != NULL)
	{
		// bind to next IPv4 address, then advance in circular list
		set_bind_sa(rctx, (struct src_prefix_list *)in4_enabled->data, &sb);
		strbuf_printf(&sb, " (next in list)");
		in4_enabled = in4_enabled->next;
	}
	else if(rctx->ctx->domain == AF_INET6 && in6_enabled != NULL)
	{
		// bind to next IPv6 address, then advance in circular list
		set_bind_sa(rctx, (struct src_prefix_list *)in4_enabled->data, &sb);
		strbuf_printf(&sb, " (next in list)");
		in6_enabled = in6_enabled->next;
	}
	else
	{	// failed
		strbuf_printf(&sb, "\n\tDid not find any available address");
	}
}

int init(mam_context_t *mctx)
{
	printf("\nPolicy module \"pipelining round robin\" is loading.\n");

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	// Let last element point to first element again to form a circular list
	if (in4_enabled != NULL)
		g_slist_last(in4_enabled)->next = in4_enabled;
	if (in6_enabled != NULL)
		g_slist_last(in6_enabled)->next = in6_enabled;

	printf("\nPolicy module \"pipelining round robin\" has been loaded.\n");
	return 0;
}

int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);

	printf("Policy module \"pipelining round robin\" cleaned up.\n");
	return 0;
}

void print_policy_info(void *policy_info)
{}

int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
	printf("\tResolve request: Not supported\n\n");
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
	return -1;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	printf("\tConnect request: Not supported\n\n");
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	return -1;
}

/** Asynchronous callback function for socketconnect request after resolve
 *  Invoked once a response to the resolver query has been received
 *  Sends back a reply to the client with the received answer
 */
static void resolve_request_result_connect(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	strbuf_t sb;
	strbuf_init(&sb);

	request_context_t *rctx = ptr;

	if (errcode) {
	    printf("\tError resolving: %s -> %s\n", rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
	}
	else
	{
		printf("\tGot resolver response for %s: %s\n",
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

		if(rctx->ctx->bind_sa_req != NULL)
		{	// already bound
			strbuf_printf(&sb, "\tAlready bound to src=");
			_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
			strbuf_printf(&sb, "\n");
		}
		else
		{
			// search address to bind to
			set_sa_rr(rctx, sb);

			if(rctx->ctx->bind_sa_suggested != NULL)
			{
				strbuf_printf(&sb, "\tSuggested address: ");
				_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_suggested, rctx->ctx->bind_sa_suggested_len);
			}	 
			else
				strbuf_printf(&sb, "\tNo address available!\n");
		}
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
 *  Sends back alternating sockets
 */
int on_socketchoose_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;

	printf("\n\tSocketchoose request\n");

	if (rctx->sockets != NULL && rctx->sockets->next != NULL)
	{
		// If we have a socket set of two or more sockets
		int suggestedsocket = rctx->sockets->file;
		struct socketlist *lastsocketlist = NULL;

		if ((lastsocketlist = _muacc_socketlist_find_file(rctx->sockets, lastsocket)) != NULL)
		{
			printf("\t(Last socket was %d ", lastsocket);
			if (lastsocketlist->next != NULL)
			{
				/* Make rctx set pointer point to the chosen socket (lastsocketlist->next) */

				struct socketlist *socket_not_chosen = rctx->sockets;
				suggestedsocket = lastsocketlist->next->file;
				rctx->sockets = lastsocketlist->next;
				printf("- choosing next one)\n");

				/* free all socketset members from rctx->set up until lastset to prevent memory leaks */
				lastsocketlist->next = NULL;
				while (socket_not_chosen != NULL)
				{
					struct socketlist *todelete = socket_not_chosen;
					socket_not_chosen = socket_not_chosen->next;

					_muacc_free_ctx(todelete->ctx);
					free(todelete);
				}
			}
			else
			{
				printf("[last in set] - choosing first one again)\n");
			}
		}
		else
		{
			printf("\t(Could not find last socket %d - choosing first one)\n", lastsocket);
		}
		printf("\tSuggest using socket %d\n\n", suggestedsocket);
		lastsocket = suggestedsocket;

		/* Provide the information to open a new similar socket, in case the suggested socket cannot be used */
		uuid_t context_id;
		__uuid_copy(context_id, rctx->ctx->ctxid);
		rctx->ctx = _muacc_clone_ctx(rctx->sockets->ctx);
		__uuid_copy(rctx->ctx->ctxid, context_id);

		_muacc_send_ctx_event(rctx, muacc_act_socketchoose_resp_existing);
	}
	else
	{
		printf("\tSocketchoose with empty or almost empty set - trying to create new socket, resolving %s:%s\n", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

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
