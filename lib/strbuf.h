/** \file  strbuf.h
 *  \brief a small string buffer for buildung up text output
 */

#ifndef __STRBUF_H__
#define __STRBUF_H__

#define STRBUF_DEFAULT_CHUNKSIZE	1024	

/** struct holding a string buffer */
typedef struct strbuf {
	int usage;			/**< usage counter */
    char *buf;          /**< backing buffer */
    size_t pos;         /**< position in buffer */
    size_t len;         /**< length of the buffer */
	size_t chunksize;   /**< chunksize for realloc */
} strbuf_t;

void strbuf_init(strbuf_t *sb);
int strbuf_retain(strbuf_t *sb);
int strbuf_release(strbuf_t *sb);

void strbuf_rewind(strbuf_t *sb);

int strbuf_vprintf(strbuf_t *sb, const char *fmt, va_list args);
int strbuf_printf(strbuf_t *sb, const char *fmt, ...);

char *strbuf_export(strbuf_t *sb);

#endif /* __STRBUF_H__ */