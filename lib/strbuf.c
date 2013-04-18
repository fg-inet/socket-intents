#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dlog.h"
#include "strbuf.h"

#define STRBUF_NOISY_DEBUG 0

void strbuf_init(strbuf_t *sb)
{
	sb->chunksize = STRBUF_DEFAULT_CHUNKSIZE;
    sb->buf = malloc(sb->chunksize*2);
	(sb->buf)[0] = 0x00;
	sb->usage = 1;
    sb->pos = 0;
    sb->len = sb->chunksize*2;
	
	DLOG(STRBUF_NOISY_DEBUG, "ran init - len=%zd pos=%zd buf=%p *buf=%s\n", sb->len, sb->pos, sb->buf, sb->buf);
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
	char *newp;
	size_t rem, newl;
	
	if(sb->buf == NULL)
	{
		DLOG(STRBUF_NOISY_DEBUG, "called with sb->buf == NULL - aborting");
		abort();
	}
	
	// calculate length
	rem = sb->len - sb->pos;
	
	// print to temp buffer
	newl = vasprintf(&newp, fmt, args);
	if(newp == NULL) return -1; // error
	
	if(newl+1 >= rem) 
	{	// was truncated 
		size_t nlen;
		
		// grow buffer
		nlen = sb->len+( (( newl / (sb->chunksize) ) +2) * (sb->chunksize));
		DLOG(STRBUF_NOISY_DEBUG, "need to grow buffer len=%zd pos=%zd rem=%zd new=%zd  new_size=%zd buf=%p\n", sb->len, sb->pos, rem, newl, nlen, sb->buf);
		
		sb->buf = realloc(sb->buf, nlen);
		if(sb->buf == NULL)
		{	// malloc error
			sb->len = 0;
			return -1;
		}

		// fix lenth
		sb->len = nlen;		
		rem = sb->len - sb->pos;
	}
	
	
	
	// overall success
	memcpy(((sb->buf)+(sb->pos)), newp, newl );
	free(newp);
	sb->pos += newl;
		
	return newl;
}


int strbuf_printf(strbuf_t *sb, const char *fmt, ...)
{
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
	DLOG(STRBUF_NOISY_DEBUG, "\nexporting buffer len=%zd pos=%zd strlen(buf)=%zd buf=%p\n",
		sb->len, sb->pos, strlen(sb->buf), sb->buf);
	return sb->buf;
}


