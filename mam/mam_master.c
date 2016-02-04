/** \file mam_master.c
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "clib/muacc.h"
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"

#include "mam_pmeasure.h"

#include "mam_configp.h"
#include "mam.h"

#define MIN_BUF (sizeof(muacc_tlv_t)+sizeof(size_t))
#define MAX_BUF 0

#ifndef MAM_MASTER_NOISY_DEBUG0
#define MAM_MASTER_NOISY_DEBUG0 1
#endif

#ifndef MAM_MASTER_NOISY_DEBUG1
#define MAM_MASTER_NOISY_DEBUG1 1
#endif

#ifndef MAM_MASTER_NOISY_DEBUG2
#define MAM_MASTER_NOISY_DEBUG2 0
#endif

struct mam_context *global_mctx = NULL;
int config_fd = -1;

void clean_client_state(GSList *client);
int compare_id_in_struct(gconstpointer list_data,  gconstpointer user_data);

static void process_mam_request(struct request_context *ctx)
{
	int (*callback_function)(request_context_t *ctx, struct event_base *base) = NULL;
	int ret;

	if (ctx->action == muacc_act_getaddrinfo_resolve_req)
	{
		/* Respond to a getaddrinfo resolve request */
		DLOG(MAM_MASTER_NOISY_DEBUG0, "Received new getaddrinfo resolve request\n");

		_mam_callback_or_fail(ctx, "on_resolve_request", MAM_POLICY_RESOLVE_CALLED, muacc_act_getaddrinfo_resolve_resp);
	}
	else if (ctx->action == muacc_act_connect_req)
	{
		/* Respond to a connect request */
		DLOG(MAM_MASTER_NOISY_DEBUG0, "Received new connect request\n");
		_mam_callback_or_fail(ctx, "on_connect_request", MAM_POLICY_CONNECT_CALLED, muacc_act_connect_resp);
	}
	else if (ctx->action == muacc_act_socketconnect_req)
	{
		/* Respond to a socketconnect request */
		DLOG(MAM_MASTER_NOISY_DEBUG0, "Received new socketconnect request\n");
		if (_mam_fetch_policy_function(ctx->mctx->policy, "on_socketconnect_request", (void **) &callback_function) == 0)
		{
			/* Call policy module function */
			DLOG(MAM_MASTER_NOISY_DEBUG2, "calling on_socketconnect_request callback\n");
			ctx->policy_calls_performed |= MAM_POLICY_SOCKETCONNECT_CALLED;
			ret = callback_function(ctx, ctx->mctx->ev_base);
			if (ret != 0)
			{
				DLOG(MAM_MASTER_NOISY_DEBUG1, "on_socketconnect_request callback returned %d\n", ret);
				_muacc_send_ctx_event(ctx, muacc_act_socketconnect_resp);
			}
		}
		else
		{
			DLOG(MAM_MASTER_NOISY_DEBUG2, "No callback on_socketconnect_request available.\n");
			int (*callback_function2)(request_context_t *ctx, struct event_base *base) = NULL;
			if (_mam_fetch_policy_function(ctx->mctx->policy, "on_resolve_request", (void **) &callback_function) == 0 && _mam_fetch_policy_function(ctx->mctx->policy, "on_connect_request", (void **) &callback_function2) == 0)
			{
				DLOG(MAM_MASTER_NOISY_DEBUG2, "Fallback to resolve_request and connect_request. \n");
				ctx->action = muacc_act_socketconnect_fallback;
				ctx->policy_calls_performed |= MAM_POLICY_RESOLVE_CALLED;
				ret = callback_function(ctx, ctx->mctx->ev_base);
				if (ret != 0)
				{
					DLOG(MAM_MASTER_NOISY_DEBUG1, "on_resolve_request callback returned %d\n", ret);
					_muacc_send_ctx_event(ctx, muacc_act_getaddrinfo_resolve_resp);
				}
			}
			else
			{
				DLOG(MAM_MASTER_NOISY_DEBUG2, "no resolve_request and connect_request available either. Sending back context\n");
				_muacc_send_ctx_event(ctx, muacc_act_socketconnect_resp);
			}
		}
	}
	else if (ctx->action == muacc_act_socketchoose_req)
	{
		DLOG(MAM_MASTER_NOISY_DEBUG0, "Received new socketchoose request\n");
		_mam_callback_or_fail(ctx, "on_socketchoose_request", MAM_POLICY_SOCKETCHOOSE_CALLED, muacc_act_socketchoose_resp_new);
	}
	else
	{
		/* Unknown request */
		DLOG(MAM_MASTER_NOISY_DEBUG1, "received unknown request (action id: %d)\n", ctx->action);
		_muacc_send_ctx_event(ctx, muacc_error_unknown_request);
	}
}

/** read next tlvs on one of mam's client sockets
 *
 */
static void mamsock_readcb(struct bufferevent *bev, void *prctx)
{
	struct request_context **rctx = (struct request_context **) prctx;
	uuid_t old;
	
#if MAM_MASTER_NOISY_DEBUG2 == 1
	char uuid_str[37];
#endif
		
    for(;;)
	{
		/* prepair stuff of this round */
		struct request_context *crctx = *rctx;
		
	    crctx->in = bufferevent_get_input(bev);
	    crctx->out = bufferevent_get_output(bev);
		
    	switch( _muacc_proc_tlv_event(crctx) )
    	{
    		case _muacc_proc_tlv_event_too_short:
    			/* need more data - wait for next read event */
    			return;
    		case _muacc_proc_tlv_event_eof:
				/* re-initialize muacc context to back up further communication (keep uuid)*/
				uuid_copy(old, crctx->ctx->ctxid);
				 
				 *rctx = malloc(sizeof(struct request_context));
				(*rctx)->sockets = NULL;
				(*rctx)->mctx = global_mctx;
				(*rctx)->ctx = _muacc_create_ctx();
				printf("in read cb\n");
    			uuid_copy((*rctx)->ctx->ctxid, old);

				if (global_mctx->clients)
				{
					GSList *client_list = g_slist_find_custom(global_mctx->clients, crctx->ctx->ctxid, compare_id_in_struct);
			
					if (client_list)
					{
						socket_list_t *sk = malloc(sizeof(socket_list_t));
						sk->sk = crctx->ctx->sockfd;

#if MAM_MASTER_NOISY_DEBUG2 == 1
						uuid_unparse_lower(crctx->ctx->ctxid, uuid_str);
						printf("(mam callback) add sockfd: %d to id: %s\n", sk->sk, uuid_str);
						((client_list_t*)client_list->data)->sockets = g_slist_append(((client_list_t*)client_list->data)->sockets, sk);
#endif
					}
				}

				/* Process the request by calling the policy */
				process_mam_request(crctx);

    			continue;
    		default:
    			/* read a TLV - are there more out there? */
    			continue;
    	}
	}
}

int compare_id_in_struct(gconstpointer list_data,  gconstpointer user_data)
{
	client_list_t *list = (client_list_t*) list_data;
	uuid_t *id = (uuid_t*) user_data;
	
	if (memcmp(&(list->id), id, sizeof(uuid_t)) == 0)
		return 0;
	
	return -1;
}

/** handle errors on one of mam's client sockets
 *
 */
static void mamsock_errorcb(struct bufferevent *bev, short error, void *ctx)
{
	struct request_context **rctx = (struct request_context **) ctx;
	struct request_context *crctx = *rctx;
	
    if (error & BEV_EVENT_EOF) {
        /* connection has been closed, do any clean up here */
		GSList *client_list = g_slist_find_custom(global_mctx->clients, crctx->ctx->ctxid, compare_id_in_struct);
		
		if (client_list)
		{
			if (((client_list_t*)client_list->data)->callback_function)
				((client_list_t*)client_list->data)->callback_function(client_list);
		}
		
    } else if (error & BEV_EVENT_ERROR) {
        /* check errno to see what error occurred */
        /* ... */
    } else if (error & BEV_EVENT_TIMEOUT) {
        /* must be a timeout event handle, handle it */
        /* ... */
    }
	if (*rctx != NULL)
	{
		mam_release_request_context(*rctx);
		free(rctx);
	}
    bufferevent_free(bev);
}

void clean_client_state(GSList *client_list)
{
#if MAM_MASTER_NOISY_DEBUG2 == 1
	char uuid_str[37];
	client_list_t *list = ((client_list_t*)client_list->data);
	uuid_unparse_lower(list->id, uuid_str);
	printf("cleaning up state for client with fd:%d and id: %s\n", list->client_sk, uuid_str);
#endif
	
	global_mctx->clients = g_slist_remove(global_mctx->clients, client_list->data);
}

/** accept new clients of mam
 *
 */
static void do_accept(evutil_socket_t listener, short event, void *arg)
{
    mam_context_t *mctx = arg;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
	client_list_t *client_list;
	
    int fd = accept(listener, (struct sockaddr*)&ss, &slen);
    if (fd < 0) {
        perror("accept");
    } else if (fd > FD_SETSIZE) {
        close(fd);
    } else {

		DLOG(MAM_MASTER_NOISY_DEBUG2, "Accepted client %d\n", fd);
    	struct bufferevent *bev;
		request_context_t **ctx;

		/* initialize request context to back up communication */
		ctx = malloc(sizeof(struct request_context *));		
		*ctx = malloc(sizeof(struct request_context));
		(*ctx)->ctx = _muacc_create_ctx();
		(*ctx)->mctx = mctx;
				
		client_list = malloc(sizeof(client_list_t));
		client_list->client_sk = fd; //bufferevent_getfd(bev);
		uuid_generate((*ctx)->ctx->ctxid);
		uuid_copy(client_list->id, (*ctx)->ctx->ctxid);
		client_list->callback_function = &clean_client_state;
		client_list->sockets = NULL;
		global_mctx->clients = g_slist_append(global_mctx->clients, client_list);
						
		(*ctx)->sockets = NULL;
		(*ctx)->policy_calls_performed = 0;

    	/* set up bufferevent magic */
        evutil_make_socket_nonblocking(fd);
        bev = bufferevent_socket_new(mctx->ev_base, fd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(bev, mamsock_readcb, NULL, mamsock_errorcb, (void *) ctx);
        bufferevent_setwatermark(bev, EV_READ, MIN_BUF, MAX_BUF);
        bufferevent_enable(bev, EV_READ|EV_WRITE);
		printf("do_accept done\n");
    }
}


static int do_listen(mam_context_t *ctx, evutil_socket_t listener, struct sockaddr *sin, size_t sin_z)
{
    struct event *listener_event;
    struct stat buf;
    char *path = ((struct sockaddr_un *)sin)->sun_path;

    evutil_make_socket_nonblocking(listener);

    /* Check if socket already exists */
    if (path != NULL && stat(path, &buf) == 0)
    {
        // Old file exists
        if (S_ISSOCK(buf.st_mode))
        {
            // Old file is a socket - delete it to make room for a new one
            DLOG(MAM_MASTER_NOISY_DEBUG2, "Socket on %s already exists - Unlinking\n", path);
            unlink(path);
        }
        else
        {
            // Old file is not a socket - just print an error message.
            DLOG(MAM_MASTER_NOISY_DEBUG1, "Cannot listen on %s: File exists \n", path);
            return -1;
        }
    }

    if (bind(listener, sin, sin_z)) {
        perror("bind");
        return -1;
    }

    if (listen(listener, 16)<0) {
        perror("listen");
        return -1;
    }

    listener_event = event_new(ctx->ev_base, listener, EV_READ|EV_PERSIST, do_accept, (void*) ctx);
    event_add(listener_event, NULL);

	return 0;

}

/** Initialize the dynamic loader using libltdl,
 *  load the policy module from a file given by filename
 *  and call its init() function
 */
static int setup_policy_module(mam_context_t *ctx, const char *filename)
{
	DLOG(MAM_MASTER_NOISY_DEBUG2, "setting up policy module %s \n", filename);

	const char *ltdl_error = NULL;

	lt_dlhandle mam_policy;
	int (*init_function)() = NULL;

	if (NULL != (mam_policy = lt_dlopen(filename)))
	{
		DLOG(MAM_MASTER_NOISY_DEBUG2, "policy module has been loaded successfully\n");
	}
	else
	{
		ltdl_error = lt_dlerror();
		DLOG(MAM_MASTER_NOISY_DEBUG1, "loading of module failed");
		if (MAM_MASTER_NOISY_DEBUG1)
		{
			if (ltdl_error != NULL)
			{
				fprintf(stderr, ": %s", ltdl_error);
			}
			fprintf(stderr, "\n");
		}
		return -1;
	}
	
	/* publish policy */
	ctx->policy = mam_policy;
	
	if (_mam_fetch_policy_function(mam_policy, "init", (void **)&init_function) == 0)
	{
		init_function(ctx);
	}
	else
	{
		DLOG(MAM_MASTER_NOISY_DEBUG1, "module %s could not be initialized", filename);
		return -1;
	}

	
	return 0;
}

/** call policy cleanup callback and trash pointer
  */
static int cleanup_policy_module(mam_context_t *ctx) {
	
	int ret;
	int (*cleanup_function)() = NULL;
	
	if (_mam_fetch_policy_function(ctx->policy, "cleanup", (void **) &cleanup_function) == 0)
	{
		/* Call policy module function */
		DLOG(MAM_MASTER_NOISY_DEBUG1, "calling policy cleanup callback\n");
		ret = cleanup_function(ctx);
		if (ret != 0)
		{
			DLOG(1, "cleanup callback returned %d\n", ret);
		}
		return(ret);
	}
	else
	{
		DLOG(MAM_MASTER_NOISY_DEBUG1, "policy has no cleanup callback\n");
		ret = -1;
	}
	
	ctx->policy = NULL;
	return(ret);
}


/** read config an (re)load policy module
 */
static void configure_mamma() {
	
	char *policy_filename = NULL;
	
	/* clean up old policy module of present */
	if(global_mctx->policy != NULL)
	{
		DLOG(MAM_MASTER_NOISY_DEBUG1, "unloading old policy module\n");
		cleanup_policy_module(global_mctx);
	}
	
	/* get interface config from system */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "updating interface list from system\n");
	update_src_prefix_list(global_mctx);
	
	if (MAM_MASTER_NOISY_DEBUG2) mam_print_context(global_mctx);
	
	/* load policy module if we have command line arguments */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "parsing config file\n");	
	mam_read_config(config_fd, &policy_filename, global_mctx);
	
	if (MAM_MASTER_NOISY_DEBUG2) mam_print_context(global_mctx);
	
	/* initialize dynamic loader and load policy module */
	if(policy_filename != NULL)
	{
		DLOG(MAM_MASTER_NOISY_DEBUG1, "loading policy module\n");
		setup_policy_module(global_mctx, policy_filename);
	}
	else
	{
		DLOG(1, "no policy module given - mamma is useless...\n");
	}
	
	DLOG(MAM_MASTER_NOISY_DEBUG1, "(re)configuration done\n");
	
}

/** signal handler the libevent-way 
 */
static void do_graceful_shutdown(evutil_socket_t _, short what, void* evctx) {
    struct event_base *evb = (struct event_base*) evctx;
	DLOG(MAM_MASTER_NOISY_DEBUG0, "got signal - terminating...\n");
    event_base_loopexit(evb, NULL);
}

/** signal handler the libevent-way 
 */
static void do_reconfigure(evutil_socket_t _, short what, void* evctx) {
	DLOG(MAM_MASTER_NOISY_DEBUG0, "got hangup signal - reconfigureing\n");
	configure_mamma();
}

/** signal handler the libevent-way 
 */
static void do_print_state(evutil_socket_t _, short what, void* evctx) {
	DLOG(1, "got USR1 signal - dumping state\n");
	mam_print_context(global_mctx);
	g_slist_foreach(global_mctx->prefixes, &pmeasure_print_summary, NULL);
}

int
main(int c, char **v)
{
    evutil_socket_t listener;
    struct event *term_event, *int_event, *hup_event, *usr1_event;
    struct sockaddr_un sun;
	int ret;

    setvbuf(stderr, NULL, _IONBF, 0);

	/* create mam context */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "setting up mam context\n");
	global_mctx = mam_create_context();
    if (global_mctx == NULL) {
		DLOG(1, "failed to create mam context\n");
        exit(1);
    }
	
	/* set up libevent */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "setting up event base\n");
    global_mctx->ev_base = event_base_new();
    if (!global_mctx->ev_base) {
		/* will log error on it's own */
        exit(1);
    }
	
	/* configure dl */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "initializing dynamic module loader\n");
	if (0 != (ret = lt_dlinit()))
	{
		DLOG(MAM_MASTER_NOISY_DEBUG1, "initializing dynamic module loader failed with error %d\n", ret);
		exit(1);
	}
	lt_dladdsearchdir(".");
	
	/* configure default/fallback DNS base */
	global_mctx->evdns_default_base = evdns_base_new(global_mctx->ev_base, 1);
	
	/* register signal handlers with libevent */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "registering signal handlers\n");
	/* call term function on a INT or TERM signal */
	term_event = evsignal_new(global_mctx->ev_base, SIGTERM, do_graceful_shutdown, global_mctx->ev_base);
	event_add(term_event, NULL);
	int_event = evsignal_new(global_mctx->ev_base, SIGINT, do_graceful_shutdown, global_mctx->ev_base);
	event_add(int_event, NULL);
	hup_event = evsignal_new(global_mctx->ev_base, SIGHUP, do_reconfigure, global_mctx->ev_base);
	event_add(hup_event, NULL);
	usr1_event = evsignal_new(global_mctx->ev_base, SIGUSR1, do_print_state, global_mctx->ev_base);
	event_add(usr1_event, NULL);
	
	/* open config file */
	if ( c < 2 )
	{
		DLOG(1, "no config file specified\n");
		exit(1);
	}
	else if ( (config_fd = open(v[1], O_RDONLY)) == -1 )
	{
		DLOG(1, "opening config file %s failed: %s\n", v[1], strerror(errno));
		exit(1);
	} 
	
	/* apply config and read policy */
	configure_mamma();

	/* pmeasure event */
	pmeasure_setup();
	struct event *pmeasure_event;
	struct timeval ten_seconds = {10, 0};
	pmeasure_event = event_new(global_mctx->ev_base, -1, EV_PERSIST, pmeasure_callback, global_mctx);
	evtimer_add(pmeasure_event, &ten_seconds);

	/* set mam socket */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "setting up mamma's socket %s\n", MUACC_SOCKET);
	sun.sun_family = AF_UNIX;
	#ifdef HAVE_SOCKADDR_LEN
	sun.sun_len = sizeof(struct sockaddr_un);
	#endif
	strncpy( sun.sun_path, MUACC_SOCKET, sizeof(sun.sun_path));

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	
	DLOG(MAM_MASTER_NOISY_DEBUG1, "setting up listener\n");
	if( 0 > do_listen(global_mctx, listener, (struct sockaddr *)&sun, sizeof(sun)))
	{
		DLOG(1, "listen failed\n");
		return 1;
	}
	
	/* run libevent */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "running event loop\n");
    event_base_dispatch(global_mctx->ev_base);

    /* clean up */
	DLOG(MAM_MASTER_NOISY_DEBUG1, "cleaning up\n");
    close(listener);
    unlink(MUACC_SOCKET);
	cleanup_policy_module(global_mctx);
	pmeasure_cleanup();
	mam_release_context(global_mctx);
	lt_dlexit();
	DLOG(MAM_MASTER_NOISY_DEBUG1, "exiting\n");


    return 0;
}
