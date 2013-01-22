#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "../config.h"

#include "tlv.h"
#include "muacc.h"

size_t muacc_push_tlv_tag( char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag)
{
	size_t tlv_len = sizeof(muacc_tlv_t)+sizeof(size_t);

	/* check size */
	if ( *buf_pos + tlv_len >= buf_len)
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_push_tlv: buffer too small: buf_len=%li, pos=%li needed=%li\n", getpid(), (long) buf_len, (long) *buf_pos, (long) tlv_len);
		#endif
		return(-1);
	}

	*((muacc_tlv_t *) (buf + *buf_pos)) = tag;
	*buf_pos += sizeof(muacc_tlv_t);

	*((size_t *) (buf + *buf_pos)) = 0;
	*buf_pos += sizeof(size_t);

	return(tlv_len);

}

size_t muacc_push_tlv( char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag, 
	const void *data, size_t data_len)
{
	size_t tlv_len = sizeof(muacc_tlv_t)+sizeof(size_t)+data_len;
	
	/* check size */
	if ( *buf_pos + tlv_len >= buf_len)
	{
		#ifdef CLIB_NOISY_DEBUG
		fprintf(stderr, "%6d: muacc_push_tlv: buffer too small: buf_len=%li, pos=%li needed=%li\n", getpid(), (long) buf_len, (long) *buf_pos, (long) tlv_len);
		#endif
		return(-1);
	}
	
	if ( data == NULL || data_len == 0)
	{
		return 0;
	}
	
	*((muacc_tlv_t *) (buf + *buf_pos)) = tag;
	*buf_pos += sizeof(muacc_tlv_t);
	
	*((size_t *) (buf + *buf_pos)) = data_len;
	*buf_pos += sizeof(size_t);

	memcpy( (void *) (buf + *buf_pos), data,  data_len);
	*buf_pos += data_len;

	return(tlv_len);
}

size_t muacc_read_tlv( int fd, 
	char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t *tag, 
	void **data, size_t *data_len)
{
	int tlv_len;
	size_t rlen, rrem; 
	
	/* check size */
	if ( *buf_pos + sizeof(muacc_tlv_t) + sizeof(size_t) >= buf_len ) 
	{
		goto muacc_read_tlv_err;
	}
	
	/* read header */
	rlen = read(fd, buf + *buf_pos , sizeof(muacc_tlv_t) + sizeof(size_t));
	if(rlen <= 0)
	{
		perror("muacc_read_tlv header read failed:");
		goto muacc_read_tlv_err;
	} 
	else if(rlen < sizeof(muacc_tlv_t) + sizeof(size_t))
	{
		fprintf(stderr, "muacc_read_tlv header read failed: short read");
		goto muacc_read_tlv_err;
	}
	
	/* parse tag and length */ 
	*tag = *((muacc_tlv_t *) (buf + *buf_pos));
	*buf_pos += sizeof(muacc_tlv_t);
	
	*data_len = *((size_t *) (buf + *buf_pos));
	*buf_pos += sizeof(size_t);
	
	tlv_len = sizeof(muacc_tlv_t) + sizeof(size_t) + *data_len;
	
	/* check size again */
	if (*buf_pos + tlv_len >= buf_len)
	{	
		fprintf(stderr, "muacc_read_tlv read failed: buffer too small");
		goto muacc_read_tlv_err;
	}
	
	/* check EOF TLV */
	if( *tag == eof )
	{
		*data = NULL;
		*data_len = -1;
		return(0);
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

	return(tlv_len);

muacc_read_tlv_err:

	*data = NULL;
	*data_len = -1;
	return(-1);
	
}


size_t muacc_push_addrinfo_tlv( char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag, struct addrinfo *ai0)
{

    struct addrinfo *ai;
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
			*((size_t *) (buf + *buf_pos)) = strlen(ai->ai_canonname);
			*buf_pos += sizeof(size_t);
			memcpy( (void *) (buf + *buf_pos), ai->ai_canonname, strlen(ai->ai_canonname));
			*buf_pos += ai->ai_addrlen;
		}
	}	

	return(tlv_len);
}
