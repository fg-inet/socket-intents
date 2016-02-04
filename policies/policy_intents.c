/** \file policy_intents.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <stdio.h>

#include "policy.h"
#include "policy_util.h"

/* policy-specific data structure */
struct intents_info {
	enum intent_category	category;
	char					*category_string;
	int						is_default;
};

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

char addr_str[INET6_ADDRSTRLEN]; /** String for debug / error printing */

void set_sa_for_category(request_context_t *rctx, enum intent_category given, strbuf_t sb);

void print_policy_info(void *policy_info)
{
	struct intents_info *info = policy_info;
	if (info->category_string != NULL)
		printf("\t for category %s (%d)", info->category_string, (int) info->category);
	if (info->is_default)
		printf(" (default)");
}

/* Parse category information from config file and place it into policy_info of prefix */
void set_policy_info(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	struct intents_info *new = malloc(sizeof(struct intents_info));
	memset(new, 0, sizeof(struct intents_info));
	new->category = -1;

	if (spl->policy_set_dict != NULL)
	{
		/* Set category */
		gpointer value = NULL;
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

		/* Set default interface */
		if (((value = g_hash_table_lookup(spl->policy_set_dict, "default")) != NULL) && value)
			new->is_default = 1;
	}

	spl->policy_info = (void *) new;
}

/** Free the policy data structures */
void freepolicyinfo(gpointer elem, gpointer data)
{
	struct src_prefix_list *spl = elem;

	if(spl->policy_info != NULL)
	{
		if(((struct intents_info *)spl->policy_info)->category_string != NULL)
			free(((struct intents_info *)spl->policy_info)->category_string);
		free(spl->policy_info);
	}
}


/* Set the matching source address for a given category */
void set_sa_for_category(request_context_t *rctx, enum intent_category given, strbuf_t sb)
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
		struct intents_info *info = spl->policy_info;

		if (info->category == given)
		{
			/* Category matches. Set source address */
			set_bind_sa(rctx, spl, &sb);
			strbuf_printf(&sb, " for category %s (%d)", info->category_string, given);
			break;
		}
		if (info->is_default)
		{
			/* Configured as default. Store for fallback */
			defaultaddr = spl;
		}
		elem = elem->next;
	}

	if (elem == NULL)
	{
		/* No suitable address for this category was found */
		if (given >= 0 && given <= INTENT_STREAM)
			strbuf_printf(&sb, "\n\tDid not find a suitable src address for category %d", given);
		if (defaultaddr != NULL)
		{
			set_bind_sa(rctx, defaultaddr, &sb);
			strbuf_printf(&sb, " (default)");
		}
	}
}

int init(mam_context_t *mctx)
{
	printf("\nPolicy module \"intents\" is loading.\n");

	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);

	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);

	printf("\nPolicy module \"intents\" has been loaded.\n");

	return 0;
}

int cleanup(mam_context_t *mctx)
{
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);
	printf("\nPolicy module \"intents\" cleaned up.\n");
	return 0;
}

/** Asynchronous callback function for resolve request
 *  Invoked once a response to the resolver query has been received
 *  Sends back a reply to the client with the received answer
 */
static void resolve_request_result(int errcode, struct evutil_addrinfo *addr, void *ptr)
{

	request_context_t *rctx = ptr;

	if (errcode) {
	    printf("\n\tError resolving: %s -> %s\n", rctx->ctx->remote_hostname, evutil_gai_strerror(errcode));
	}
	else
	{
		printf("\n\tGot resolver response for %s: %s\n",
			rctx->ctx->remote_hostname,
			addr->ai_canonname ? addr->ai_canonname : "");

		assert(addr != NULL);
		assert(rctx->ctx->remote_addrinfo_res == NULL);
		rctx->ctx->remote_addrinfo_res = _muacc_clone_addrinfo(addr);
		evutil_freeaddrinfo(addr);
		print_addrinfo_response (rctx->ctx->remote_addrinfo_res);
	}

	// send reply
	_muacc_send_ctx_event(rctx, muacc_act_getaddrinfo_resolve_resp);
}

/** Resolve request function (mandatory)
 *  Is called upon each getaddrinfo request from a client
 *  Must send a reply back using _muacc_sent_ctx_event or register a callback that does so
 */
int on_resolve_request(request_context_t *rctx, struct event_base *base)
{
    struct evdns_getaddrinfo_request *req;

	printf("\tResolve request: %s:%s", (rctx->ctx->remote_hostname == NULL ? "" : rctx->ctx->remote_hostname), (rctx->ctx->remote_service == NULL ? "" : rctx->ctx->remote_service));

	/* Try to resolve this request using asynchronous lookup */
    req = evdns_getaddrinfo(
			rctx->mctx->evdns_default_base,
			rctx->ctx->remote_hostname,
			rctx->ctx->remote_service,
            rctx->ctx->remote_addrinfo_hint,
			&resolve_request_result,
			rctx);
	printf(" - Sending request to default nameserver\n");
    if (req == NULL) {
		/* returned immediately - Send reply to the client */
		_muacc_send_ctx_event(rctx, muacc_act_socketconnect_resp);
		printf("\tRequest failed.\n");
	}
	return 0;
}

int on_connect_request(request_context_t *rctx, struct event_base *base)
{
	strbuf_t sb;
	strbuf_init(&sb);
	strbuf_printf(&sb, "\tConnect request: dest=");
	_muacc_print_sockaddr(&sb, rctx->ctx->remote_sa, rctx->ctx->remote_sa_len);

	intent_category_t c = 0;
	socklen_t option_length = sizeof(intent_category_t);

	if (0 != mampol_get_socketopt(rctx->ctx->sockopts_current, SOL_INTENTS, INTENT_CATEGORY, &option_length, &c))
	{
		// no category given
		strbuf_printf(&sb, "\n\tNo category intent given - Setting default if applicable.");
		set_sa_for_category(rctx, -1, sb);
	}
	else if(rctx->ctx->bind_sa_req != NULL)
	{	// already bound
		strbuf_printf(&sb, "\tAlready bound to src=");
		_muacc_print_sockaddr(&sb, rctx->ctx->bind_sa_req, rctx->ctx->bind_sa_req_len);
	}

	else
	{
		// search address to bind to
		set_sa_for_category(rctx, c, sb);
	}

	// send response
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	printf("%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	return 0;
}
