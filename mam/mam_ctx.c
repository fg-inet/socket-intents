/** \file mam_ctx.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <stdio.h>
#include <errno.h>

#include "clib/dlog.h"
#include "clib/strbuf.h"
#include "clib/muacc_util.h"
#include "lib/muacc_ctx.h"

#include "mam.h"
#include "mam_util.h"

#define BUF_LEN 4096

#ifndef MAM_CTX_NOISY_DEBUG
#define MAM_CTX_NOISY_DEBUG 0
#endif

struct mam_context *mam_create_context()
{
	struct mam_context *ctx;

	if ( ( ctx = malloc(sizeof(struct mam_context)) ) == NULL)
	{
		perror("mam_context malloc failed");
		return NULL;
	}
	memset(ctx, 0x00, sizeof(struct mam_context));

	DLOG(MAM_CTX_NOISY_DEBUG, "created new ctx=%p successfully \n", (void *) ctx);

	mam_init_context(ctx);

	return ctx;
}

int mam_init_context(struct mam_context *ctx)
{
	DLOG(MAM_CTX_NOISY_DEBUG, "initializing MAM context %p\n", (void *) ctx);

	ctx->usage = 1;
	//TODO

	ctx->state = g_hash_table_new(NULL, NULL);

	return 0;
}

int mam_release_context(struct mam_context *ctx)
{
	DLOG(MAM_CTX_NOISY_DEBUG, "releasing context %p\n", (void *) ctx);

	if (ctx == NULL)
	{
		DLOG(MAM_CTX_NOISY_DEBUG, "WARNING: tried to release NULL pointer context\n");
		return -1;
	}
	else
	{
		if ( --(ctx->usage) == 0)
		{
			_mam_free_ctx(ctx);
			return 0;
		}
		else
		{
			DLOG(MAM_CTX_NOISY_DEBUG, "context still has %d references\n", ctx->usage);
			return ctx->usage;
		}
	}
}

void mam_print_context(mam_context_t *ctx)
{
	strbuf_t sb;

	if (ctx == NULL)
	{
		printf("ctx == NULL\n");
	}
	else
	{
		strbuf_init(&sb);
		_mam_print_ctx(&sb, ctx);
		printf("%s\n/*eof*/\n", strbuf_export(&sb));
		strbuf_release(&sb);
	}
}

void mam_print_request_context(request_context_t *ctx)
{
	strbuf_t sb;

	// printf("/**************************************/\n");
	if (ctx == NULL)
	{
		printf("ctx == NULL\n");
		return;
	}

	strbuf_init(&sb);
	
	if (ctx->ctx == NULL)
	{
		strbuf_printf(&sb, "ctx->ctx == NULL\n");
	}
	else
	{
		_muacc_print_ctx(&sb, ctx->ctx);
	}

	if (ctx->mctx == NULL)
	{
		strbuf_printf(&sb, "ctx->mctx == NULL\n");
	}
	else
	{
		strbuf_printf(&sb, "ctx->mctx == %p\n", ctx->mctx);
		//_mam_print_ctx(&sb, ctx->mctx);
	}
	printf("%s\n", strbuf_export(&sb));
	strbuf_release(&sb);
	// printf("/**************************************/\n");

}

void mam_release_request_context(request_context_t *ctx)
{
	/* clean up old _muacc_ctx */
	_muacc_free_ctx(ctx->ctx);

	/* clean up socket list */
	while (ctx->sockets != NULL)
	{
		struct socketlist *socklist = ctx->sockets;
		ctx->sockets = socklist->next;

		_muacc_free_ctx(socklist->ctx);
		free(socklist);
	}

	free(ctx);
}

