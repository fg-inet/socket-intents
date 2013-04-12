/**
 * \file mam_master.c
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <ltdl.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "../config.h"

#include "../lib/muacc.h"
#include "../lib/muacc_ctx.h"
#include "../lib/muacc_tlv.h"
#include "../lib/dlog.h"

#include "mam_util.h"

#define MIN_BUF (sizeof(muacc_tlv_t)+sizeof(size_t))
#define MAX_BUF 0

#ifndef MAM_MASTER_NOISY_DEBUG0
#define MAM_MASTER_NOISY_DEBUG0 0
#endif

#ifndef MAM_MASTER_NOISY_DEBUG1
#define MAM_MASTER_NOISY_DEBUG1 0
#endif

#ifndef MAM_MASTER_NOISY_DEBUG2
#define MAM_MASTER_NOISY_DEBUG2 0
#endif

struct event_base *base = NULL;

void process_mam_request(struct request_context *ctx)
{
	struct _muacc_ctx *_new_ctx;
	int (*callback_function)(request_context_t *ctx, struct event_base *base) = NULL;
	int ret;

	if (ctx->action == muacc_act_getaddrinfo_resolve_req)
	{
		/* Respond to a getaddrinfo resolve request */
		DLOG(MAM_MASTER_NOISY_DEBUG2, "received getaddrinfo resolve request\n");
		if (_mam_fetch_policy_function(ctx->mctx->policy, "on_resolve_request", (void **) &callback_function) == 0)
		{
			/* Call policy module function */
			DLOG(MAM_MASTER_NOISY_DEBUG2, "calling on_resolve_request callback\n");
			ret = callback_function(ctx, base);
			if (ret != 0)
			{
				DLOG(MAM_MASTER_NOISY_DEBUG1, "on_resolve_request callback returned %d\n", ret);
			}
		}
		else
		{
			DLOG(MAM_MASTER_NOISY_DEBUG2, "no callback on_resolve_request available. Sending back ctx\n");
			_muacc_send_ctx_event(ctx, muacc_act_getaddrinfo_resolve_resp);
		}
	}
	else if (ctx->action == muacc_act_connect_req)
	{
		/* Respond to a connect request */
		DLOG(MAM_MASTER_NOISY_DEBUG2, "received connect request\n");
		if (_mam_fetch_policy_function(ctx->mctx->policy, "on_connect_request", (void **) &callback_function) == 0)
		{
			/* Call policy module function */
			DLOG(MAM_MASTER_NOISY_DEBUG2, "calling on_connect_request callback\n");
			ret = callback_function(ctx, base);
			if (ret != 0)
			{
				DLOG(MAM_MASTER_NOISY_DEBUG1, "on_connect_request callback returned %d\n", ret);
			}
		}
		else
		{
			DLOG(MAM_MASTER_NOISY_DEBUG2, "no callback on_connect_request available. Sending back ctx\n");
			_muacc_send_ctx_event(ctx, muacc_act_connect_resp);
		}
	}
	else
	{
		/* Unknown request */
		DLOG(MAM_MASTER_NOISY_DEBUG1, "received unknown request (action id: %d\n", ctx->action);
	}
	
	/* re-initialize muacc context to back up further communication */
	_new_ctx = _muacc_create_ctx();

	/* clean up old _muacc_ctx */
	_muacc_free_ctx(ctx->ctx);

	ctx->ctx = _new_ctx;

}

/** read next tlvs on one of mam's client sockets
 *
 */
void mamsock_readcb(struct bufferevent *bev, void *ctx)
{
	struct request_context *rctx = (struct request_context *) ctx;

    rctx->in = bufferevent_get_input(bev);
    rctx->out = bufferevent_get_output(bev);

    for(;;)
    switch( _muacc_proc_tlv_event(rctx) )
    {
    	case _muacc_proc_tlv_event_too_short:
    		/* need more data - wait for next read event */
    		return;
    	case _muacc_proc_tlv_event_eof:
    		/* done processing - do MAM's magic */
			process_mam_request(rctx);
    		continue;
    	default:
    		/* read a TLV - are there more out there? */
    		continue;
    }
}

/** handle errors on one of mam's client sockets
 *
 */
void mamsock_errorcb(struct bufferevent *bev, short error, void *ctx)
{
	struct request_context *rctx = (struct request_context *) ctx;

    if (error & BEV_EVENT_EOF) {
        /* connection has been closed, do any clean up here */
        /* ... */
    } else if (error & BEV_EVENT_ERROR) {
        /* check errno to see what error occurred */
        /* ... */
    } else if (error & BEV_EVENT_TIMEOUT) {
        /* must be a timeout event handle, handle it */
        /* ... */
    }
	if (rctx->ctx != NULL)		_muacc_free_ctx(rctx->ctx);
	if (rctx != NULL)			free(rctx);
    bufferevent_free(bev);
}

/** accept new clients of mam
 *
 */
void do_accept(evutil_socket_t listener, short event, void *arg)
{
    mam_context_t *mctx = arg;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listener, (struct sockaddr*)&ss, &slen);
    if (fd < 0) {
        perror("accept");
    } else if (fd > FD_SETSIZE) {
        close(fd);
    } else {

		DLOG(MAM_MASTER_NOISY_DEBUG2, "Accepted client %d\n", fd);
    	struct bufferevent *bev;
		request_context_t *ctx;

		/* initialize request context to back up communication */
		ctx = malloc(sizeof(struct request_context));
		ctx->ctx = _muacc_create_ctx();
		ctx->mctx = mctx;

    	/* set up bufferevent magic */
        evutil_make_socket_nonblocking(fd);
        bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(bev, mamsock_readcb, NULL, mamsock_errorcb, (void *) ctx);
        bufferevent_setwatermark(bev, EV_READ, MIN_BUF, MAX_BUF);
        bufferevent_enable(bev, EV_READ|EV_WRITE);

    }
}


int do_listen(mam_context_t *ctx, evutil_socket_t listener, struct sockaddr *sin, size_t sin_z)
{
    struct event *listener_event;

    evutil_make_socket_nonblocking(listener);

    if (bind(listener, sin, sin_z)) {
        perror("bind");
        return -1;
    }

    if (listen(listener, 16)<0) {
        perror("listen");
        return -1;
    }

    listener_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*) ctx);
    event_add(listener_event, NULL);

	return 0;

}

/** Initialize the dynamic loader using libltdl,
 *  load the policy module from a file given by filename
 *  and call its init() function
 */
int setup_policy_module(mam_context_t *ctx, const char *filename)
{
	DLOG(MAM_MASTER_NOISY_DEBUG2, "setting up policy module %s \n", filename);

	int ret = -1;
	const char *ltdl_error = NULL;

	lt_dlhandle mam_policy;
	int (*init_function)() = NULL;

	if (0 != (ret = lt_dlinit()))
	{
		DLOG(MAM_MASTER_NOISY_DEBUG1, "Initializing dynamic module loader failed with %d errors\n", ret);
		return -1;
	}

	lt_dladdsearchdir(".");
	if (NULL != (mam_policy = lt_dlopen(filename)))
	{
		DLOG(MAM_MASTER_NOISY_DEBUG2, "policy module has been loaded successfully\n");
		ctx->policy = mam_policy;
	}
	else
	{
		ltdl_error = lt_dlerror();
		DLOG(MAM_MASTER_NOISY_DEBUG1, "loading of module failed");
		if (MAM_MASTER_NOISY_DEBUG1)
		{
			if (ltdl_error != NULL)
			{
				printf(": %s", ltdl_error);
			}
			printf("\n");
		}
		return -1;
	}

	if (_mam_fetch_policy_function(ctx->policy, "init", (void **)&init_function) == 0)
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

/** signal handler the libevent-way 
 */
static void do_graceful_shutdown(evutil_socket_t _, short what, void* ctx) {
    struct event_base *evb = (struct event_base*) ctx;
	DLOG(MAM_MASTER_NOISY_DEBUG0, "got signal - terminating...\n");
    event_base_loopexit(evb, NULL);
}

int
main(int c, char **v)
{
    evutil_socket_t listener;
    struct event *term_event, *int_event;
    struct sockaddr_un sun;
	struct mam_context *ctx = NULL;

    setvbuf(stderr, NULL, _IONBF, 0);

	DLOG(MAM_MASTER_NOISY_DEBUG2, "creating and initializing mam context...\n");
	ctx = mam_create_context();
    if (ctx == NULL) {
		DLOG(MAM_MASTER_NOISY_DEBUG0, "failed to create mam context\n");
        exit(1);
    }

	DLOG(MAM_MASTER_NOISY_DEBUG2, "setting up event base...\n");
	/* set up libevent */
    base = event_base_new();
    if (!base) {
		/* will log error on it's own */
        exit(1);
    }

	/* set mam socket */
	DLOG(MAM_MASTER_NOISY_DEBUG0, "setting up mamma's socket %s ...\n", MUACC_SOCKET);
	sun.sun_family = AF_UNIX;
	#ifdef HAVE_SOCKADDR_LEN
	sun.sun_len = sizeof(struct sockaddr_un);
	#endif
	strncpy( sun.sun_path, MUACC_SOCKET, sizeof(sun.sun_path));

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	DLOG(MAM_MASTER_NOISY_DEBUG2, "setting up listener...\n");
	if( 0 > do_listen(ctx, listener, (struct sockaddr *)&sun, sizeof(sun)))
	{
		DLOG(MAM_MASTER_NOISY_DEBUG1, "listen failed\n");
		return 1;
	}

	/* call term function on a INT or TERM signal */
	term_event = evsignal_new(base, SIGTERM, do_graceful_shutdown, base);
	event_add(term_event, NULL);
	int_event = evsignal_new(base, SIGINT, do_graceful_shutdown, base);
	event_add(int_event, NULL);

 	/* get interface config from system */
	update_src_prefix_list(ctx);

	/* load policy module if we have command line arguments */
	if (c > 1)
	{
		/* initialize dynamic loader and load policy module */
		setup_policy_module(ctx, v[1]);
	}

	/* run libevent */
	DLOG(MAM_MASTER_NOISY_DEBUG2, "running event loop...\n");
    event_base_dispatch(base);

    /* clean up */
    close(listener);
    unlink(MUACC_SOCKET);
	mam_release_context(ctx);
	lt_dlexit();

    return 0;
}
