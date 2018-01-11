/** \file strbuf.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dlog.h"
#include "strbuf.h"

#define STRBUF_NOISY_DEBUG 0
#define STRBUF_DEFAULT_CHUNKSIZE	512	

void strbuf_init(strbuf_t *sb)
{
	sb->chunksize = STRBUF_DEFAULT_CHUNKSIZE;
    sb->buf = malloc(sb->chunksize*2);
	(sb->buf)[0] = 0x00;
	sb->usage = 1;
    sb->pos = 0;
    sb->len = sb->chunksize*2;
	
	DLOG(STRBUF_NOISY_DEBUG, "init buf=%p len=%zd pos=%zd *buf=%s\n",sb->buf, sb->len, sb->pos, sb->buf);
}

int strbuf_retain(strbuf_t *sb)
{
	return ++(sb->usage);
}

int strbuf_release(strbuf_t *sb)
{
	if (--(sb->usage) > 0)
		return sb->usage;
	else
	{
		if(sb->buf != NULL)
			free(sb->buf);
	    sb->pos = 0;
	    sb->len = 0;
		return 0;
	}
}
	
int strbuf_vprintf(strbuf_t *sb, const char *fmt, va_list args)
{
	size_t rem, newl;
	
	if(sb->buf == NULL)
	{
		DLOG(STRBUF_NOISY_DEBUG, "called with sb->buf == NULL - aborting");
		abort();
	}
	
	// calculate length
	rem = sb->len - sb->pos;
	
	if(rem < sb->chunksize) 
	{	// need to grow 
		
		// grow buffer
		size_t nlen = (sb->len)+(sb->chunksize)*2;
		DLOG(STRBUF_NOISY_DEBUG, "grow buffer buf=%p pos=%zd old_len=%zd rem=%zd new_len=%zd chunksize=%zd \n", sb->buf, sb->pos, sb->len, rem, nlen, sb->chunksize);
		
		sb->buf = realloc(sb->buf, nlen);
		if(sb->buf == NULL)
		{	// malloc error
			sb->len = 0;
			return -1;
		}

		// fix lenth
		sb->len = nlen;		
    }
	
	// print to buffer
	newl = vsnprintf((sb->buf)+(sb->pos), sb->chunksize, fmt, args);
	
	if(newl < sb->chunksize)
	{
		sb->pos += newl;	
		return newl;
	} else {
		sb->chunksize = newl+1;	
		return strbuf_vprintf(sb, fmt, args);	
	}
}


int strbuf_printf(strbuf_t *sb, const char *fmt, ...)
{
	if (sb == NULL)
	{
		return 0;
	}
	int ret;
	va_list args;
	va_start(args,fmt);
	ret = strbuf_vprintf(sb, fmt, args);
	va_end(args);
	return ret;
}

void strbuf_rewind(strbuf_t *sb)
{
	sb->pos = 0;
}


char *strbuf_export(strbuf_t *sb)
{
	DLOG(STRBUF_NOISY_DEBUG, "\nexporting buf=%p len=%zd pos=%zd strlen(buf)=%zd \n",
		sb->buf, sb->len, sb->pos, strlen(sb->buf));
	return sb->buf;
}


