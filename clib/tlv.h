#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef enum 
{
	eof = 0x00,		    	/* end of TLV data – always 0 bytes */
	action,					/* action triggering request */	
	bind_sa_req = 0x12, 	/* local address requested */
	bind_sa_res,        	/* local address choosen by mam */
	remote_hostname = 0x20,	/* remote host name */
	remote_srvname,	   		/* remote service name */
	remote_sa_req,     		/* remote address requested */
	remote_addrinfo_hint,	/* candidate remote addresses (sorted by mam preference) */
	remote_addrinfo_res,	/* candidate remote addresses (sorted by mam preference) */
	remote_sa_res     		/* remote address choosen */	
} muacc_tlv_t;;
	
typedef enum 
{
	muacc_action_connect,
	muacc_action_getaddrinfo,
	muacc_action_setsocketopt
} muacc_mam_action_t;;


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
size_t muacc_push_tlv (char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag, 
	const void *data, size_t data_len);
	
size_t muacc_read_tlv( int fd, 
 	char *buf, size_t *buf_pos, size_t buf_len,
 	muacc_tlv_t *tag, 
 	void **data, size_t *data_len);

	
/** deep copy addrinfo into TLV
 *
 */
size_t muacc_push_addrinfo_tlv (char *buf, size_t *buf_pos, size_t buf_len,
	muacc_tlv_t tag, struct addrinfo *ai0);