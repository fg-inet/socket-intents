#include "muacc.h"
#include <string.h>
#include "../config.h"

/** push data in an TLV buffer
 *
 * @param buf		pointer to buffer to pu data
 * @param buf_pos	pointer to current offset to which the buffer is already used (in/out)
 * @param buf_len	length of the buffer
 * @param tag		tag of the data
 * @param data 		data to be pushed into the buffer          - will result in a no-op if NULL
 * @param data_len 	lengh of data to be pushed into the buffer - will result in a no-op if 0
 *
 * @return length of the added tlv, -1 if there was an error.
 */
size_t muacc_push_tlv( char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag, 
	const void *data, size_t data_len)
{
	int tlv_len = sizeof(muacc_tlv_t)+sizeof(size_t)+data_len;
	
	/* check size */
	if ( *buf_pos + tlv_len >= buf_len)
	{
		return(-1);
	}
	
	if ( data == NULL || data_len == 0 )
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

size_t muacc_pop_tlv( const char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t *tag, 
	const void **data, size_t *data_len)
{
	int tlv_len;
	
	/* check size */
	if ( *buf_pos + sizeof(muacc_tlv_t) + sizeof(size_t) >= buf_len ) 
	{
		*data = NULL;
		*data_len = -1;
		return(-1);
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
		*data = NULL;
		*data_len = -1;
		return(-1);
	}
	
	/* check EOF TLV */
	if( *tag == eof )
	{
		*data = NULL;
		*data_len = -1;
		return(0);
	}
	
	*data = ( (void *) (buf + *buf_pos), data,  data_len);
	*buf_pos += *data_len;

	return(tlv_len);
}

/** deep copy addrinfo into TLV
 *
 */
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
