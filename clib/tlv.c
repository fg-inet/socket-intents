#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "../config.h"

#include "tlv.h"
#include "muacc.h"
#include "dlog.h"


#define TLV_NOISY_DEBUG 1


inline size_t muacc_push_tlv_tag( char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag)
{
	return muacc_push_tlv(buf, buf_pos, buf_len, tag, NULL, 0);

}

size_t muacc_push_tlv( char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag, 
	const void *data, size_t data_len)
{
	size_t tlv_len = sizeof(muacc_tlv_t)+sizeof(size_t)+data_len;
	
	/* check size */
	if ( *buf_pos + tlv_len >= buf_len)
	{
		DLOG(TLV_NOISY_DEBUG, "buffer too small: buf_len=%li, pos=%li needed=%li\n", (long) buf_len, (long) *buf_pos, (long) tlv_len);
		return(-1);
	}
	
	*((muacc_tlv_t *) (buf + *buf_pos)) = tag;
	*buf_pos += sizeof(muacc_tlv_t);
	
	*((size_t *) (buf + *buf_pos)) = data_len;
	*buf_pos += sizeof(size_t);

	#ifdef TLV_NOISY_DEBUG
	if(data == NULL && data_len != 0)
		fprintf(stderr, "%6d: muacc_push_tlv: WARNING: trying to push NULL to a non zero length TLV\n", getpid());
	#endif

	if(data_len != 0)
	{
		memcpy( (void *) (buf + *buf_pos), data,  data_len);
		*buf_pos += data_len;
	}

	DLOG(TLV_NOISY_DEBUG, "put tlv: buf_pos=%ld tag=%x data_len=%ld tlv_len=%ld \n", *buf_pos, tag, data_len, tlv_len);

	return(tlv_len);
}

size_t muacc_read_tlv( int fd, 
	char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t *tag, 
	void **data, size_t *data_len)
{
	size_t tlv_len;
	size_t rlen, rrem; 
	
	DLOG(TLV_NOISY_DEBUG, "invoked - buf_pos=%ld\n", *buf_pos);

	/* check size */
	if ( *buf_pos + sizeof(muacc_tlv_t) + sizeof(size_t) >= buf_len ) 
	{
		fprintf(stderr, "%6d: muacc_read_tlv header read failed: buffer too small\n", (int) getpid());
		goto muacc_read_tlv_err;
	}
	
	/* read header */
	rlen = read(fd, (buf + *buf_pos) , (sizeof(muacc_tlv_t) + sizeof(size_t)) );
	if(rlen <= 0)
	{
		perror("muacc_read_tlv header read failed:");
		goto muacc_read_tlv_err;
	} 
	else if(rlen < sizeof(muacc_tlv_t) + sizeof(size_t))
	{
		fprintf(stderr, "%6d: muacc_read_tlv header read failed: short read\n", (int) getpid() );
		goto muacc_read_tlv_err;
	}
	
	/* parse tag and length */ 
	*tag = *((muacc_tlv_t *) (buf + *buf_pos));
	*buf_pos += sizeof(muacc_tlv_t);
	
	*data_len = *((size_t *) (buf + *buf_pos));
	*buf_pos += sizeof(size_t);
	
	tlv_len = sizeof(muacc_tlv_t) + sizeof(size_t) + *data_len;
	
	DLOG(TLV_NOISY_DEBUG, "read header - buf_pos=%ld tag=%x, data_len=%ld tlv_len=%ld \n" , *buf_pos, *tag, *data_len, tlv_len);

	/* check size again */
	if (*buf_pos + *data_len >= buf_len)
	{	
		fprintf(stderr, "%6d: muacc_read_tlv read failed: buffer too small\n", (int) getpid() );
		goto muacc_read_tlv_err;
	}
	
	/* check EOF TLV */
	if( *tag == eof )
	{
		DLOG(TLV_NOISY_DEBUG, "found data_len==0 - returning 0\n");
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
			perror("muacc_read_tlv data read failed:");
			goto muacc_read_tlv_err;
		}
		rrem     -= rlen;
		*buf_pos += rlen;
	}

	DLOG(TLV_NOISY_DEBUG, "read data done - buf_pos=%ld tag=%x, data_len=%ld tlv_len=%ld \n" , *buf_pos, *tag, *data_len, tlv_len);

	return(tlv_len);

muacc_read_tlv_err:

	*data = NULL;
	*data_len = -1;
	return(-1);
	
}


size_t muacc_push_addrinfo_tlv( char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag, const struct addrinfo *ai0)
{

    const struct addrinfo *ai;
	size_t data_len = 0; 
	size_t tlv_len = -1; 
	
	if ( ai0 == NULL )
	{
		return 0;
	}
	
	/* calculate size */
    for (ai = ai0; ai; ai = ai->ai_next) 
	{	
		data_len += sizeof(struct addrinfo) + ai->ai_addrlen + (ai->ai_canonname != NULL)?( sizeof(size_t) + strlen(ai->ai_canonname) ):0; 
	}
	
	/* check size */
	tlv_len = sizeof(muacc_tlv_t)+sizeof(size_t)+data_len;
	if ( *buf_pos + tlv_len >= buf_len)
	{
		return(-1);
	}
	
	/* write tag */	
	*((muacc_tlv_t *) (buf + *buf_pos)) = tag;
	*buf_pos += sizeof(muacc_tlv_t);
	
	*((size_t *) (buf + *buf_pos)) = data_len;
	*buf_pos += sizeof(size_t);
	
	/* deep copy struct 
	 *
	 * data is arranged as followed:
	 * 			struct addrinfo ai
	 *			struct sockaddr ai->ai_addr      if ai->ai_addr != NULL, length known from ai->ai_addrlen
	 * 			size_t strlen(ai->ai_canonname)  if ai->ai_canonname != NULL
	 *          string ai->ai_canonname			 if ai->ai_canonname != NULL
	 *          ... next struct if ai->ai_next != NULL ...
	 */
    for (ai = ai0; ai; ai = ai->ai_next) 
	{	
		memcpy( (void *) (buf + *buf_pos), ai, sizeof(struct addrinfo));
		*buf_pos += sizeof(struct addrinfo);
		if ( ai->ai_addr != NULL) 
		{
			memcpy( (void *) (buf + *buf_pos), ai->ai_addr, ai->ai_addrlen);
			*buf_pos += ai->ai_addrlen;
		}
		if ( ai->ai_canonname != NULL) 
		{
			size_t sl = strlen(ai->ai_canonname)+1;
			*((size_t *) (buf + *buf_pos)) = sl;
			*buf_pos += sizeof(size_t);
			memcpy( (void *) (buf + *buf_pos), ai->ai_canonname, sl);
			*buf_pos += sl;
		}
	}	

	return(tlv_len);
}

size_t muacc_extract_addrinfo_tlv( const char *data, size_t data_len, struct addrinfo **ai0)
{
	struct addrinfo **ai1 = ai0;

	size_t data_pos = 0;
	struct addrinfo *ai;

	size_t allocated = 0;

	for( ; ai->ai_next != NULL ; )
	{

		/* check length */
		if (data_len-data_pos < sizeof(struct addrinfo))
		{
			DLOG(TLV_NOISY_DEBUG, "data_len too short - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", data_pos, data_len, sizeof(struct addrinfo));
			return(-1);
		}

		/* get memory and copy struct */
		if( (ai = malloc(sizeof(struct addrinfo))) == NULL )
			goto muacc_extract_addrinfo_tlv_malloc_failed;
		allocated += sizeof(struct addrinfo);
		memcpy( ai, (void *) (data + data_pos),sizeof(struct addrinfo));
		data_pos += sizeof(struct addrinfo);

		/* addrinfo */
		if ( ai->ai_addr != NULL)
		{
			/* check length again */
			if (data_len-data_pos < ai->ai_addrlen)
			{
				DLOG(TLV_NOISY_DEBUG, "data_len too short while extracting ai_addr - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", data_pos, data_len, sizeof(struct addrinfo));
				goto muacc_extract_addrinfo_tlv_length_failed;
			}
			/* get memory and copy struct */
			if( (ai->ai_addr = malloc(ai->ai_addrlen)) == NULL )
				goto muacc_extract_addrinfo_tlv_malloc_failed;
			allocated += ai->ai_addrlen;
			memcpy( ai->ai_addr,  (void *) (data + data_pos), ai->ai_addrlen);
			data_pos += ai->ai_addrlen;
		}

		/* ai_canonname */
		if ( ai->ai_canonname != NULL)
		{
			/* check length again */
			if (data_len-data_pos < sizeof(size_t))
			{
				DLOG(TLV_NOISY_DEBUG, " data_len too short while extracting ai_canonname_len - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", data_pos, data_len, sizeof(struct addrinfo));
				goto muacc_extract_addrinfo_tlv_length_failed;
			}
			/* get string length + trailing\0 */
			size_t canonname_len = *((size_t *) (data + data_pos));
			data_pos += sizeof(size_t);

			/* check length again */
			if (data_len-data_pos < canonname_len)
			{
				DLOG(TLV_NOISY_DEBUG, "data_len too short while extracting ai_canonname - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", data_pos, data_len, sizeof(struct addrinfo));
				goto muacc_extract_addrinfo_tlv_length_failed;
			}
			if( (ai->ai_canonname = malloc(canonname_len)) == NULL )
				goto muacc_extract_addrinfo_tlv_malloc_failed;
			allocated += canonname_len;
			memcpy( ai->ai_canonname, (void *) (data + data_pos), canonname_len);
			*((ai->ai_canonname)+canonname_len-1) = 0x00;
			data_pos += canonname_len;
		}

		/* fix pointers */
		ai->ai_next = NULL;
		*ai1 = ai;
		ai1 = &(ai->ai_next);

	}

    return allocated;

    muacc_extract_addrinfo_tlv_malloc_failed:
    muacc_extract_addrinfo_tlv_length_failed:

    *ai0 = NULL;
    return -1;

}

size_t muacc_extract_socketaddr_tlv( const char *data, size_t data_len, struct sockaddr **sa0)
{

	size_t data_pos = 0;

	/* check length */
	if (data_len-data_pos < sizeof(struct addrinfo))
	{
		DLOG(TLV_NOISY_DEBUG, "data_len too short - data_pos=%ld data_len=%ld sizeof(struct addrinfo)=%ld\n", data_pos, data_len, sizeof(struct addrinfo));
		return(-1);
	}

	/* get memory and copy struct */
	if( (*sa0 = malloc(data_len)) == NULL )
		goto muacc_extract_socketaddr_tlv_malloc_failed;
	memcpy( *sa0, (void *) (data + data_pos),data_len);
	data_pos += data_len;

	return(data_len);

	muacc_extract_socketaddr_tlv_malloc_failed:
	*sa0 = NULL;
	return(-1);

}
