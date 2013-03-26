#include <stdio.h>
#include <errno.h>

#include "../clib/dlog.h"
#include "../clib/muacc_util.h"
#include "mam.h"
#include "mam_util.h"

#define BUF_LEN 4096

#ifndef MAM_CTX_NOISY_DEBUG
#define MAM_CTX_NOISY_DEBUG 1
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
	char buf[BUF_LEN] = {0};
	size_t buf_len = BUF_LEN;
	size_t buf_pos = 0;

	if (ctx == NULL)
	{
		printf("ctx == NULL\n");
	}
	else
	{
		_mam_print_ctx(buf, &buf_pos, buf_len, ctx);
		printf("/**************************************/\n%s\n/**************************************/\n", buf);
	}
}
