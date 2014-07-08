#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

#include "clib/muacc_client.h"

#include "muacc_tlv.h"
#include "muacc_util.h"

#include "dlog.h"

#ifndef MUACC_TLV_NOISY_DEBUG0
#define MUACC_TLV_NOISY_DEBUG0 1
#endif

#ifndef MUACC_TLV_NOISY_DEBUG1
#define MUACC_TLV_NOISY_DEBUG1 0
#endif

#ifndef MUACC_TLV_NOISY_DEBUG2
#define MUACC_TLV_NOISY_DEBUG2 0
#endif


ssize_t _muacc_push_tlv_tag( char *buf, ssize_t *buf_pos, ssize_t buf_len,
	muacc_tlv_t tag)
{
	return _muacc_push_tlv(buf, buf_pos, buf_len, tag, NULL, 0);

}

ssize_t _muacc_push_tlv( char *buf, ssize_t *buf_pos, ssize_t buf_len,
	muacc_tlv_t tag,
	const void *data, ssize_t data_len)
{
	ssize_t tlv_len = sizeof(muacc_tlv_t)+sizeof(ssize_t)+data_len;

	/* check size */
	if (buf == NULL)
	{
		/* checking case */
		DLOG(MUACC_TLV_NOISY_DEBUG1, "length checking done - total length is %ld - returning\n", (long) data_len);
		return(tlv_len);
	}
	else if ( *buf_pos + tlv_len >= buf_len)
	{
		DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: buffer too small: buf_len=%li, pos=%li needed=%li\n", (long) buf_len, (long) *buf_pos, (long) tlv_len);
		return(-1);
	}

	*((muacc_tlv_t *) (buf + *buf_pos)) = tag;
	*buf_pos += sizeof(muacc_tlv_t);

	*((ssize_t *) (buf + *buf_pos)) = data_len;
	*buf_pos += sizeof(ssize_t);

	if(data == NULL && data_len != 0)
	{
		DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: trying to push NULL to a non zero length TLV\n");
	}
	else if(data_len != 0)
	{
		memcpy( (void *) (buf + *buf_pos), data,  data_len);
		*buf_pos += data_len;
	}

	DLOG(MUACC_TLV_NOISY_DEBUG2, "put tlv: buf_pos=%ld tag=%x data_len=%ld tlv_len=%ld \n", (long int) *buf_pos, tag, (long int) data_len, (long int) tlv_len);

	return(tlv_len);
}


ssize_t _muacc_push_addrinfo_tlv( char *buf, ssize_t *buf_pos, ssize_t buf_len,
	muacc_tlv_t tag, const struct addrinfo *ai0)
{

    const struct addrinfo *ai;
	ssize_t data_len = 0;
	ssize_t tlv_len = 0;

	DLOG(MUACC_TLV_NOISY_DEBUG1, "invoked buf_pos=%ld buf_len=%ld ai=%p\n", (long) *buf_pos, (long) buf_len, (void *) ai0);

	if ( ai0 == NULL )
	{
		return 0;
	}

	/* calculate size */
    for (ai = ai0; ai != NULL; ai = ai->ai_next)
	{
		ssize_t i = 0;

		i += sizeof(struct addrinfo);
		i += ai->ai_addrlen;
		if(ai->ai_canonname != NULL)
			i += strlen(ai->ai_canonname);

		DLOG(MUACC_TLV_NOISY_DEBUG2, "calculated  length of  addrinfo at %p is %ld\n", (void *) ai, (long) i);
		data_len += i;
	}

	DLOG(MUACC_TLV_NOISY_DEBUG2, "total data length is %ld\n", (long) data_len);

	/* check size */
	tlv_len = sizeof(muacc_tlv_t)+sizeof(ssize_t)+data_len;
	if (buf == NULL)
	{
		/* checking case */
		DLOG(MUACC_TLV_NOISY_DEBUG1, "length checking done - total length is %ld - returning\n", (long) data_len);
		return(tlv_len);
	}
	else if ( *buf_pos + tlv_len >= buf_len)
	{
		return(-1);
	}

	/* write tag */
	*((muacc_tlv_t *) (buf + *buf_pos)) = tag;
	*buf_pos += sizeof(muacc_tlv_t);

	*((ssize_t *) (buf + *buf_pos)) = data_len;
	*buf_pos += sizeof(ssize_t);

	/* deep copy struct */
    for (ai = ai0; ai != NULL; ai = ai->ai_next)
	{
		DLOG(MUACC_TLV_NOISY_DEBUG2, "copy addrinfo at %p to tlv buf_pos=%ld buf_len=%ld\n", (void *) ai, (long) *buf_pos, (long) buf_len);

		memcpy( (void *) (buf + *buf_pos), ai, sizeof(struct addrinfo));
		*buf_pos += sizeof(struct addrinfo);
		if ( ai->ai_addr != NULL)
		{
			memcpy( (void *) (buf + *buf_pos), ai->ai_addr, ai->ai_addrlen);
			*buf_pos += ai->ai_addrlen;
		}
		if ( ai->ai_canonname != NULL)
		{
			ssize_t sl = strlen(ai->ai_canonname)+1;
			*((ssize_t *) (buf + *buf_pos)) = sl;
			*buf_pos += sizeof(ssize_t);
			memcpy( (void *) (buf + *buf_pos), ai->ai_canonname, sl);
			*buf_pos += sl;
		}
	}

	DLOG(MUACC_TLV_NOISY_DEBUG1, "done total length copied was %ld - returning\n", (long) tlv_len);

	return(tlv_len);
}

ssize_t _muacc_push_socketopt_tlv( char *buf, ssize_t *buf_pos, ssize_t buf_len,
	muacc_tlv_t tag, const struct socketopt *so0)
{

    const struct socketopt *so;
	ssize_t data_len = 0;
	ssize_t tlv_len = 0;

	DLOG(MUACC_TLV_NOISY_DEBUG1, "invoked buf_pos=%ld buf_len=%ld ai=%p\n", (long) *buf_pos, (long) buf_len, (void *) so0);

	if (so0 == NULL)
	{
		return 0;
	}

	/* calculate size */
    for (so = so0; so != NULL; so = so->next)
	{
		ssize_t i = sizeof(struct socketopt);

		if (so->optlen != 0 && so->optval != NULL)
			i += so->optlen;

		DLOG(MUACC_TLV_NOISY_DEBUG2, "calculated  length of  socketopt at %p is %ld\n", (void *) so, (long) i);
		data_len += i;
	}

    DLOG(MUACC_TLV_NOISY_DEBUG2, "total data length is %ld\n", (long) data_len);

	/* check size */
	tlv_len = sizeof(muacc_tlv_t)+sizeof(ssize_t)+data_len;
	if (buf == NULL)
	{
		/* checking case */
		DLOG(MUACC_TLV_NOISY_DEBUG1, "length checking done - total length is %ld - returning\n", (long) data_len);
		return(tlv_len);
	}
	else if ( *buf_pos + tlv_len >= buf_len)
	{
		return(-1);
	}

	/* write tag */
	*((muacc_tlv_t *) (buf + *buf_pos)) = tag;
	*buf_pos += sizeof(muacc_tlv_t);

	*((ssize_t *) (buf + *buf_pos)) = data_len;
	*buf_pos += sizeof(ssize_t);

	/* deep copy struct */
    for (so = so0; so != NULL; so = so->next)
	{
		memcpy((buf+ *buf_pos), so, sizeof(struct socketopt));
		*buf_pos += sizeof(struct socketopt);

		if (so->optlen != 0 && so->optval != NULL)
		{
			memcpy((buf+ *buf_pos), so->optval, so->optlen);
			*buf_pos += so->optlen;
		}
	}

	DLOG(MUACC_TLV_NOISY_DEBUG1, "done total length used was %ld - returning\n", (long) tlv_len);
	return(tlv_len);

}

ssize_t _muacc_extract_addrinfo_tlv( const char *data, ssize_t data_len, struct addrinfo **ai0)
{
	struct addrinfo **ai1 = ai0;

	ssize_t data_pos = 0;
	struct addrinfo *ai;

	ssize_t allocated = 0;

	DLOG(MUACC_TLV_NOISY_DEBUG1, "invoked data_len=%ld\n", (long) data_len);

	do
	{

        /* sentinels for error handling */
        ai = NULL;
        *ai1 = NULL;

		/* check length */
		if (data_len-data_pos < sizeof(struct addrinfo))
		{
			DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: data_len too short - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", (long int) data_pos, (long int) data_len, (long int) sizeof(struct addrinfo));
			goto muacc_extract_addrinfo_tlv_failed;
		}

		/* get memory and copy struct */
		if( (ai = malloc(sizeof(struct addrinfo))) == NULL )
			goto muacc_extract_addrinfo_tlv_failed;
		allocated += sizeof(struct addrinfo);
		memcpy( ai, (void *) (data + data_pos),sizeof(struct addrinfo));
		data_pos += sizeof(struct addrinfo);

		DLOG(MUACC_TLV_NOISY_DEBUG2, "copied addrinfo to %p\n", (void *) ai);

		/* addrinfo */
		if ( ai->ai_addr != NULL)
		{
			ai->ai_addr = NULL;

			/* check length again */
			if (data_len-data_pos < ai->ai_addrlen)
			{
				DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: data_len too short while extracting ai_addr - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", (long int) data_pos, (long int) data_len, (long int) sizeof(struct addrinfo));
				ai->ai_canonname = NULL;
				goto muacc_extract_addrinfo_tlv_failed;
			}
			/* get memory and copy struct */
			if( (ai->ai_addr = malloc(ai->ai_addrlen)) == NULL )
				goto muacc_extract_addrinfo_tlv_failed;
			allocated += ai->ai_addrlen;
			memcpy( ai->ai_addr,  (void *) (data + data_pos), ai->ai_addrlen);
			data_pos += ai->ai_addrlen;

			DLOG(MUACC_TLV_NOISY_DEBUG2, "copied addrinfo ai_addr to %p\n", (void *) ai->ai_addr);

		}

		/* ai_canonname */
		if ( ai->ai_canonname != NULL)
		{
			ai->ai_canonname = NULL;

			/* check length again */
			if (data_len-data_pos < sizeof(ssize_t))
			{
				DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: data_len too short while extracting ai_canonname_len - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", (long int) data_pos, (long int) data_len, (long int) sizeof(struct addrinfo));
				goto muacc_extract_addrinfo_tlv_failed;
			}
			/* get string length + trailing\0 */
			ssize_t canonname_len = *((ssize_t *) (data + data_pos));
			data_pos += sizeof(ssize_t);

			/* check length again */
			if (data_len-data_pos < canonname_len)
			{
				DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING data_len too short while extracting ai_canonname - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", (long int) data_pos, (long int) data_len, (long int) sizeof(struct addrinfo));
				goto muacc_extract_addrinfo_tlv_failed;
			}
			if( (ai->ai_canonname = malloc(canonname_len)) == NULL )
				goto muacc_extract_addrinfo_tlv_failed;
			allocated += canonname_len;
			memcpy( ai->ai_canonname, (void *) (data + data_pos), canonname_len);
			*((ai->ai_canonname)+canonname_len-1) = 0x00;
			data_pos += canonname_len;

			DLOG(MUACC_TLV_NOISY_DEBUG2, "copied addrinfo ai_canonname to %p (%s)\n", (void *) ai->ai_canonname, ai->ai_canonname);

		}

		/* fix pointers */
		*ai1 = ai;
		ai1 = &(ai->ai_next);

	} while (ai->ai_next != NULL);

	DLOG(MUACC_TLV_NOISY_DEBUG1, "done - %ld bytes allocated\n", (long) allocated);

    return allocated;

    muacc_extract_addrinfo_tlv_failed:
    if (*ai0 != NULL) freeaddrinfo(*ai0); /* cleanup chain already parsed */
    if (*ai0 != ai && ai != NULL) freeaddrinfo(ai); /* cleanup entry that failed to parse (missing in chain) */
    *ai0 = NULL;
    return -1;

}

ssize_t _muacc_extract_socketaddr_tlv( const char *data, ssize_t data_len, struct sockaddr **sa0)
{


	/* check length */
	if (data_len < sizeof(struct sockaddr))
	{
		DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: data_len too short - data_len=%ld sizeof(struct sockaddr)=%ld\n", (long int) data_len, (long int) sizeof(struct sockaddr));
		return(-1);
	}

	/* get memory and copy struct */
	if( (*sa0 = malloc(data_len)) == NULL )
		goto muacc_extract_socketaddr_tlv_malloc_failed;
	memcpy( *sa0, (void *) data ,data_len);

	return(data_len);

	muacc_extract_socketaddr_tlv_malloc_failed:
	*sa0 = NULL;
	return(-1);

}

ssize_t _muacc_extract_socketopt_tlv( const char *data, ssize_t data_len, struct socketopt **so0)
{
	struct socketopt **so1 = so0;

	ssize_t data_pos = 0;
	struct socketopt *so;

	ssize_t allocated = 0;

	DLOG(MUACC_TLV_NOISY_DEBUG1, "invoked data_len=%ld\n", (long) data_len);

	do
	{
		/* for cleanup in _muacc_extract_socketopt_tlv_parse_failed */
		so = NULL;

		/* check length */
		if (data_len-data_pos < sizeof(struct socketopt))
		{
			DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: data_len too short - data_pos=%ld data_len=%ld sizeof(struct socketopt)=%ld\n", (long int) data_pos, (long int) data_len, (long int) sizeof(struct socketopt));
			*so1 = NULL;
			goto _muacc_extract_socketopt_tlv_parse_failed;
		}

		/* get memory and copy struct */
		if( (so = malloc(sizeof(struct socketopt))) == NULL )
			goto _muacc_extract_socketopt_tlv_malloc_failed;
		allocated += sizeof(struct socketopt);
		memcpy( so, (void *) (data + data_pos),sizeof(struct socketopt));
		data_pos += sizeof(struct socketopt);

		DLOG(MUACC_TLV_NOISY_DEBUG2, "copied socketaddr to %p\n", (void *) so);

		/* check and set option pointer */
		if(so->optlen > 0 && so->optval != NULL)
		{
			if(data_len-data_pos < so->optlen ) {
				DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: so->optlen too large for data_len - data_pos=%ld data_len=%ld so->optlen=%ld\n", (long int) data_pos, (long int) data_len, (long int) so->optlen);
				so->optval = NULL;
				so->next = NULL;
				goto _muacc_extract_socketopt_tlv_parse_failed;
			}

			if( (so->optval = malloc(so->optlen)) == NULL )
				goto _muacc_extract_socketopt_tlv_parse_failed;

			memcpy(so->optval, (void *) (data + data_pos), so->optlen );
			data_pos += so->optlen;

			DLOG(MUACC_TLV_NOISY_DEBUG2, "copied %u bytes of data to %p\n", so->optlen, (void *) so->optval);
		}

		/* weave pointer magic */
		*so1 = so;
		so1 = &(so->next);

	} while(so->next != NULL);

	DLOG(MUACC_TLV_NOISY_DEBUG1, "done - %ld bytes allocated\n", (long) allocated);

	return(allocated);

	_muacc_extract_socketopt_tlv_parse_failed:
	_muacc_free_socketopts(*so0);
    if(*so0 != so) _muacc_free_socketopts(so);
	*so0 = NULL;
	return(-1);

	_muacc_extract_socketopt_tlv_malloc_failed:
	*so0 = NULL;
	return(-1);

}

ssize_t _muacc_read_tlv( int fd,
	char *buf, ssize_t *buf_pos, ssize_t buf_len,
	muacc_tlv_t *tag,
	void **data, ssize_t *data_len)
{
	ssize_t tlv_len;
	ssize_t rlen, rrem;

	DLOG(MUACC_TLV_NOISY_DEBUG1, "invoked - buf_pos=%ld\n", (long int) *buf_pos);

	/* check size */
	if ( *buf_pos + sizeof(muacc_tlv_t) + sizeof(ssize_t) >= buf_len )
	{
		DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: header read failed: buffer too small\n");
		goto muacc_read_tlv_err;
	}

	/* read header */
	rlen = read(fd, (buf + *buf_pos) , (sizeof(muacc_tlv_t) + sizeof(ssize_t)) );
	if(rlen <= 0)
	{
		DLOG(MUACC_TLV_NOISY_DEBUG0, "ERROR: header read failed: %s \n", strerror(errno));
		goto muacc_read_tlv_err;
	}
	else if(rlen < sizeof(muacc_tlv_t) + sizeof(ssize_t))
	{
		DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: header read failed: short read\n");
		goto muacc_read_tlv_err;
	}

	/* parse tag and length */
	*tag = *((muacc_tlv_t *) (buf + *buf_pos));
	*buf_pos += sizeof(muacc_tlv_t);

	*data_len = *((ssize_t *) (buf + *buf_pos));
	*buf_pos += sizeof(ssize_t);

	tlv_len = sizeof(muacc_tlv_t) + sizeof(ssize_t) + *data_len;

	DLOG(MUACC_TLV_NOISY_DEBUG1, "read header - buf_pos=%ld tag=%x, data_len=%ld tlv_len=%ld \n" , (long int) *buf_pos, *tag, (long int) *data_len, (long int) tlv_len);

	/* check size again */
	if (*buf_pos + *data_len >= buf_len)
	{
		DLOG(MUACC_TLV_NOISY_DEBUG0, "WARNING: read failed: buffer too small\n");
		goto muacc_read_tlv_err;
	}

	/* check EOF TLV */
	if( *tag == eof )
	{
		DLOG(MUACC_TLV_NOISY_DEBUG1, "found eof - returning\n");
		*data = NULL;
		*data_len = 0;
		return(tlv_len);
	}

	/* update data pointer */
	*data = ( (void *) (buf + *buf_pos));

	/* read data */
	rrem = *data_len;
	while(rrem > 0)
	{
		rlen = read(fd, buf + *buf_pos , rrem);
		if(rlen <= 0)
		{
			DLOG(MUACC_TLV_NOISY_DEBUG0, "ERROR: data read failed: %s \n", strerror(errno));
			goto muacc_read_tlv_err;
		}
		rrem     -= rlen;
		*buf_pos += rlen;
	}

	DLOG(MUACC_TLV_NOISY_DEBUG1, "read data done - buf_pos=%ld tag=%x, data_len=%ld tlv_len=%ld \n" , (long int) *buf_pos, *tag, (long int) *data_len, (long int) tlv_len);

	return(tlv_len);

muacc_read_tlv_err:

	*data = NULL;
	*data_len = -1;
	return(-1);

}
