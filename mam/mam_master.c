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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "../config.h"

#include "../clib/muacc.h"
#include "../clib/muacc_ctx.h"
#include "../clib/muacc_tlv.h"
#include "../clib/dlog.h"


#define MIN_BUF (sizeof(muacc_tlv_t)+sizeof(size_t))
#define MAX_BUF 0

#ifndef MAM_IF_NOISY_DEBUG0
#define MAM_IF_NOISY_DEBUG0 0
#endif

#ifndef MAM_IF_NOISY_DEBUG1
#define MAM_IF_NOISY_DEBUG1 0
#endif

#ifndef MAM_IF_NOISY_DEBUG2
#define MAM_IF_NOISY_DEBUG2 0
#endif

void process_mam_request(struct _muacc_ctx **_ctx)
{
	char buf[4096] = {0};
	size_t buf_len = 4096;
	size_t buf_pos = 0;
	struct _muacc_ctx *_new_ctx;

	_muacc_print_ctx(buf, &buf_pos, buf_len, *_ctx);
	printf("/**************************************/\n%s\n", buf);
	_muacc_send_ctx_event(*_ctx, (*_ctx)->state);
	
	/* re-initalize muacc context to back up further communication */
	_new_ctx = _muacc_create_ctx();
	_new_ctx->in  = (*_ctx)->in;
	_new_ctx->out = (*_ctx)->out;
	
	/* clean up old one without closing socket */
	_muacc_free_ctx(*_ctx);

	*_ctx = _new_ctx;
}

/** read next tlvs on one of mam's client sockets
 *
 */
void mamsock_readcb(struct bufferevent *bev, void *ctx)
{
	struct _muacc_ctx **_ctx = (struct _muacc_ctx **) ctx;

    struct evbuffer *input, *output;

    input = bufferevent_get_input(bev);
    output = bufferevent_get_output(bev);

    for(;;)
    switch( _muacc_proc_tlv_event(input, output, *_ctx) )
    {
    	case _muacc_proc_tlv_event_too_short:
    		/* need more data - wait for next read event */
    		return;
    	case _muacc_proc_tlv_event_eof:
    		/* done processing - do MAM's magic */
    		process_mam_request(_ctx);
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
	struct _muacc_ctx *_ctx = (struct _muacc_ctx *) ctx;

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
	_muacc_free_ctx(_ctx);
    bufferevent_free(bev);
}

/** accept new clients of mam
 *
 */
void do_accept(evutil_socket_t listener, short event, void *arg)
{
    struct event_base *base = arg;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listener, (struct sockaddr*)&ss, &slen);
    if (fd < 0) {
        perror("accept");
    } else if (fd > FD_SETSIZE) {
        close(fd);
    } else {

		DLOG(MAM_IF_NOISY_DEBUG2, "Accepted client %d\n", fd);
    	struct bufferevent *bev;
    	struct _muacc_ctx **_ctx;

    	/* initalize muacc context to back up communication */
		_ctx = malloc(sizeof(struct _muacc_ctx *));
    	*_ctx = _muacc_create_ctx();

    	/* set up bufferevent magic */
        evutil_make_socket_nonblocking(fd);
        bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(bev, mamsock_readcb, NULL, mamsock_errorcb, (void *) _ctx);
        bufferevent_setwatermark(bev, EV_READ, MIN_BUF, MAX_BUF);
        bufferevent_enable(bev, EV_READ|EV_WRITE);

    }
}


int do_listen(struct event_base *base, evutil_socket_t listener, struct sockaddr *sin, size_t sin_z)
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

    listener_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)base);
    event_add(listener_event, NULL);

	return 0;

}

static void do_graceful_shutdown(evutil_socket_t _, short what, void* ctx) {
    struct event_base *evb = (struct event_base*) ctx;
	DLOG(MAM_IF_NOISY_DEBUG0, "got signal - terminating...\n");
    event_base_loopexit(evb, NULL);
}

int
main(int c, char **v)
{
    evutil_socket_t listener;
    struct event *term_event, *int_event;
    struct sockaddr_un sun;
    struct event_base *base;

    setvbuf(stderr, NULL, _IONBF, 0);

	DLOG(MAM_IF_NOISY_DEBUG2, "setting up event base...\n");
	/* set up libevent */
    base = event_base_new();
    if (!base) {
		/* will log error on it's own */
        exit(1);
    }

	/* set mam socket */
	DLOG(MAM_IF_NOISY_DEBUG0, "setting up mamma's socket %s ...\n", MUACC_SOCKET);
	sun.sun_family = AF_UNIX;
	#ifdef HAVE_SOCKADDR_LEN
	sun.sun_len = sizeof(struct sockaddr_un);
	#endif
	strncpy( sun.sun_path, MUACC_SOCKET, sizeof(sun.sun_path));

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	DLOG(MAM_IF_NOISY_DEBUG2, "setting up listener...\n");
	if( 0 > do_listen(base, listener, (struct sockaddr *)&sun, sizeof(sun)))
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "listen failed\n");
		return 1;
	}

	/* call term function on a INT or TERM signal */
	term_event = evsignal_new(base, SIGTERM, do_graceful_shutdown, base);
	event_add(term_event, NULL);
	int_event = evsignal_new(base, SIGINT, do_graceful_shutdown, base);
	event_add(int_event, NULL);

	/* run libevent */
	DLOG(MAM_IF_NOISY_DEBUG2, "running event loop...\n");
    event_base_dispatch(base);

    /* clean up */
    close(listener);
    unlink(MUACC_SOCKET);

    return 0;
}
