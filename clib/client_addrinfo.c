/** \file client_addrinfo.c
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt,
 *  Mirko Palmer, and Tobias Kaiser.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>

#include "dlog.h"
#include "muacc_ctx.h"
#include "muacc_tlv.h"
#include "muacc_util.h"
#include "intents.h"

#include "client_util.h"
#include "client_addrinfo.h"
#include "config.h"

#ifndef CLIB_IF_NOISY_DEBUG0
#define CLIB_IF_NOISY_DEBUG0 1
#endif

#ifndef CLIB_IF_NOISY_DEBUG1
#define CLIB_IF_NOISY_DEBUG1 1
#endif

#ifndef CLIB_IF_NOISY_DEBUG2
#define CLIB_IF_NOISY_DEBUG2 1
#endif


int muacc_ai_getaddrinfo(const char *hostname, const char *service,
    const struct muacc_addrinfo *hints, struct muacc_addrinfo **result)
{
	muacc_context_t ctx;

	DLOG(CLIB_IF_NOISY_DEBUG0, "muacc_getaddrinfo2 invoked.\n");

    /* Step 1: Make a MuAcc context */
	muacc_init_context(&ctx);
	if (ctx.ctx == NULL)
	{
        errno=EPROTO; /* This _might_ be as a protocol error :) */
		return EAI_SYSTEM;
	}
	DLOG(CLIB_IF_NOISY_DEBUG2, "Context created\n");




    /* Step 2: Distinguish between: 0 hints given, 1 hint given. */
    struct muacc_addrinfo defaultHints;
    memset(&defaultHints, 0, sizeof(struct muacc_addrinfo));
    defaultHints.ai_family=AF_UNSPEC;
    defaultHints.ai_socktype=SOCK_STREAM; /* How about something more generic
    here? */

    if(hints==NULL)
    {
		DLOG(CLIB_IF_NOISY_DEBUG2, "No hints given, using default hints\n");
        /* No hints given, use default hints */
        hints=&defaultHints;
    }
    else
    {
        /* Hints given, so we are good to go! */
		DLOG(CLIB_IF_NOISY_DEBUG2, "hints given, using that one\n");
    }
    /* Multiple hints are not supported by getaddrinfo, as ai_next should be
     * NULL (see following asserts) */

    /* In the hints, all members except for flags, family, socktype, socketopts
     * and protocol should be NULL or 0: */
    assert(hints->ai_addrlen==0);
    assert(hints->ai_addr==NULL);
    assert(hints->ai_canonname==0);
    assert(hints->ai_bindaddr==NULL);
    assert(hints->ai_bindaddrlen==0);
    assert(hints->ai_next==NULL);

    /* Step 3: Initialize context with values from hints... */
	ctx.ctx->domain = hints->ai_family;
	ctx.ctx->type = hints->ai_socktype;
	ctx.ctx->protocol = hints->ai_protocol;
	ctx.ctx->sockopts_current = _muacc_clone_socketopts(
        (const struct socketopt*) hints->ai_sockopts);

    /* ...and set the hostname and service! */
    if(service==NULL)
    {
        service="0"; /* Getaddrinfo is commonly called with service=NULL. */
    }
	if (_muacc_host_serv_to_ctx(&ctx, hostname, strlen(hostname), service,
        strlen(service)) != 0)
	{
		DLOG(CLIB_IF_NOISY_DEBUG2, "No hostname and service given this time!\n");
	}

    /* Step 4: Contact the MAM (blocking!) */
    if(_muacc_contact_mam(muacc_act_socketconnect_req, &ctx)==-1)
    {
        DLOG(CLIB_IF_NOISY_DEBUG1, "Got no response from MAM (Is it running?) - Failing.\n");
        errno=EPROTO;
        return EAI_SYSTEM;
        /* TODO: Maybe we should return EAI_FAIL instead of EAI_SYSTEM, since
         * not a 'real' system error, but rather an error in getaddrinfo
         * occured. */
    }

    /* Step 5: Did we get a result remote_sa? If not => return */
    if(ctx.ctx->remote_sa == NULL)
    {
        return EAI_NONAME;
    }

    /* Step 6: Allocate a muacc_addrinfo for the result */
    assert((*result)==NULL);

    *result=malloc(sizeof(struct muacc_addrinfo));
    if(*result==NULL)
    {
        return EAI_MEMORY;
    }
    memset(*result, 0, sizeof(struct muacc_addrinfo));
    (*result)->ai_sockopts=_muacc_clone_socketopts(ctx.ctx->sockopts_suggested);
    if(((*result)->ai_sockopts==NULL) &&
        (ctx.ctx->sockopts_suggested!=NULL))
    {
        /* muacc_clone_socketopts failed to allocate memory. */
        free(*result);
        *result=NULL;
        return EAI_MEMORY;
    }

    (*result)->ai_flags=0;
    (*result)->ai_next=NULL;

    (*result)->ai_family=ctx.ctx->domain;
    (*result)->ai_socktype=ctx.ctx->type;
    (*result)->ai_protocol=ctx.ctx->protocol;

    if(ctx.ctx->bind_sa_suggested)
    {
        // Copy bind_sa_suggested to ai_bindaddr
        if(ctx.ctx->bind_sa_suggested_len>sizeof(struct sockaddr_storage)) {
            DLOG(CLIB_IF_NOISY_DEBUG1, "Warning: bind_sa_suggested_len seems too long. "
                "We won't copy it!\n");
        } else {

            (*result)->ai_bindaddrlen=ctx.ctx->bind_sa_suggested_len;
            (*result)->ai_bindaddr=malloc((*result)->ai_bindaddrlen);
            if((*result)->ai_bindaddr==NULL) {
                _muacc_free_socketopts((*result)->ai_sockopts);
                (*result)->ai_sockopts=NULL;
                free(*result);
                *result=NULL;
                return EAI_MEMORY;
            }
            memcpy((*result)->ai_bindaddr, ctx.ctx->bind_sa_suggested,
                (*result)->ai_bindaddrlen);
        }
    }
    else
    {
        (*result)->ai_bindaddrlen=0;
        (*result)->ai_bindaddr=0;
    }

    if(ctx.ctx->remote_sa)
    {
        // Copy remote_sa to ai_addr
        if(ctx.ctx->remote_sa_len>sizeof(struct sockaddr_storage)) {
            DLOG(CLIB_IF_NOISY_DEBUG1, "Warning: remote_sa_len seems too long. "
                "We won't copy it!\n");
        } else {

            (*result)->ai_addrlen=ctx.ctx->remote_sa_len;
            (*result)->ai_addr=malloc((*result)->ai_bindaddrlen);
            if((*result)->ai_addr==NULL) {
                if((*result)->ai_bindaddr) {
                    free((*result)->ai_bindaddr);
                    (*result)->ai_bindaddr=NULL;
                }
                _muacc_free_socketopts((*result)->ai_sockopts);
                (*result)->ai_sockopts=NULL;
                free(*result);
                *result=NULL;
                return EAI_MEMORY;
            }
            memcpy((*result)->ai_addr, ctx.ctx->remote_sa,
                (*result)->ai_addrlen);
        }
    }
    else
    {
        DLOG(CLIB_IF_NOISY_DEBUG1, "First it seemed like we had a remote_sa, "
            "now we don't?");
        /* We should never come here, since we are not going to generate a
         * result in case we received no remote socket address. */
        abort();

        /* (*result)->ai_addrlen=0;
         * (*result)->ai_addr=0; */
    }
    (*result)->ai_canonname=0; /* Unsupported at the moment. */

    return 0;
}

void muacc_ai_freeaddrinfo(struct muacc_addrinfo *ai)
{
    assert(ai!=NULL);
    assert(ai->ai_next==NULL); /* as our getaddrinfo only returns one address,
    we only have to free one. */
    
    if(ai->ai_addr) {
        free(ai->ai_addr);
        ai->ai_addr=NULL;
    }

    if(ai->ai_bindaddr) {
        free(ai->ai_bindaddr);
        ai->ai_bindaddr=NULL;
    }

    _muacc_free_socketopts(ai->ai_sockopts);
    ai->ai_sockopts=NULL;
    free(ai);
}

int muacc_ai_setsockopts(int fd, struct socketopt *sockopts)
{
     DLOG(CLIB_IF_NOISY_DEBUG2, "muacc_ai_setsockopts called\n");
    struct socketopt *so;
    for (so = sockopts; so != NULL; so = so->next)
    {
        if(so->level==SOL_INTENTS)
        {
             DLOG(CLIB_IF_NOISY_DEBUG2, "Attempt to set intent on socket without muacc context"
                " - this does not make sense, failing muacc_ai_setsockopts.\n");
             return -1;
        }
        so->returnvalue=setsockopt(fd, so->level, so->optname, so->optval, so->optlen);
        if (so->returnvalue == -1)
        {
            DLOG(CLIB_IF_NOISY_DEBUG1, "Setting sockopt failed: %s\n", strerror(errno));
            if (so->flags && SOCKOPT_OPTIONAL != 0)
            {
                // fail
                DLOG(CLIB_IF_NOISY_DEBUG2, "Socket option was mandatory, but failed - returning\n");
                return -1;
            }
        }
        else
        {
            DLOG(CLIB_IF_NOISY_DEBUG2, "Socket option was set successfully\n");
            so->flags &= SOCKOPT_IS_SET;
        }
    }
    return 0; /* Success! */
}

struct socketopt *muacc_ai_clonesockopts(struct socketopt *sockopts)
{
    return _muacc_clone_socketopts((const struct socketopt*) sockopts);
}

void muacc_ai_freesockopts(struct socketopt *sockopts)
{
    _muacc_free_socketopts(sockopts);
}

static int simple_connect(int fd, struct muacc_addrinfo *ai, int nonblock)
{
    if(bind(fd, ai->ai_bindaddr, ai->ai_bindaddrlen)!=0)
    {
        return -1;
    }

    if(muacc_ai_setsockopts(fd, ai->ai_sockopts)!=0)
    {
        return -1;
    }

    /* Make sure connect will be non-blocking. */
    
    if(nonblock)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if(flags==-1)
        {
            return -1;
        }
        if(fcntl(fd, F_SETFL, flags | O_NONBLOCK)==-1)
        {
            return -1;
        }
    }

    if(connect(fd, ai->ai_addr, ai->ai_addrlen)!=0)
    {
        return -1;
    }
    return 0;
}

int muacc_ai_simple_connect(int fd, struct muacc_addrinfo *ai)
{
    return simple_connect(fd, ai, 0);
}

int muacc_ai_simple_connect_a(int fd, struct muacc_addrinfo *ai)
{
    return simple_connect(fd, ai, 1);
}
