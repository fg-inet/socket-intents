#include "muacc.h"
#include <string.h>
#include "../config.h"

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
	if( *tag == eof ){
		*data = NULL;
		*data_len = -1;
		return(0);
	}
	
	*data = ( (void *) (buf + *buf_pos), data,  data_len);
	*buf_pos += *data_len;

	return(tlv_len);
}