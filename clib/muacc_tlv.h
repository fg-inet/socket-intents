#ifndef __MUACC_TLV_H__
#define __MUACC_TLV_H__ 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef enum
{
	eof = 0x00,		    	/**< end of TLV data – always 0 bytes */
	action,					/**< action triggering request */
	bind_sa_req = 0x12, 	/**< local address requested */
	bind_sa_res,        	/**< local address choosen by mam */
	remote_hostname = 0x20,	/**< remote host name */
	remote_srvname,	   		/**< remote service name */
	remote_sa_req,     		/**< remote address requested */
	remote_addrinfo_hint,	/**< candidate remote addresses (sorted by mam preference) */
	remote_addrinfo_res,	/**< candidate remote addresses (sorted by mam preference) */
	remote_sa_res     		/**< remote address choosen */
} muacc_tlv_t;
	
typedef enum 
{
	muacc_action_connect,					/**< is from a connect */
	muacc_action_getaddrinfo_preresolve,	/**< is from a getaddrinfo, pre resolving */
	muacc_action_getaddrinfo_postresolve,	/**< is from a getaddrinfo, post resolving,
											  *     only called if muacc_action_getaddrinfo_preresolve did not
											  *     provide an address after calling getaddrinfo ourselves */
	muacc_action_setsocketopt				/**< is from a setsocketopt */
} muacc_mam_action_t;

/** push data in an TLV buffer
 *
 * @return length of the added tlv, -1 if there was an error.
 */
size_t _muacc_push_tlv (
	char *buf,         /**< [in]	 pointer to buffer to put data */
	size_t *buf_pos,   /**< [in,out] pointer to current offset to which the buffer is already used (in/out) */
	size_t buf_len,    /**< [in]	 length of the buffer */
	muacc_tlv_t tag,   /**< [in]	 tag of the data */
	const void *data,  /**< [in]	 data to be pushed into the buffer */
	size_t data_len    /**< [in]	 lengh of data to be pushed into the buffer */
);

/** push flag in an TLV buffer
 *
 * @return length of the added tlv, -1 if there was an error.
 */
size_t _muacc_push_tlv_tag( 
	char *buf,         /**< [in]     	pointer to buffer to put data */
	size_t *buf_pos,   /**< [in,out]    pointer to current offset to which the buffer is already used */
	size_t buf_len,    /**< [in]    	length of the buffer */
	muacc_tlv_t tag    /**< [in]    	tag to push */
);

/** push flag in an TLV buffer
 *
 * @param fd		[in]     file descriptor to read from
 * @param buf		[in]     pointer to buffer to put data
 * @param buf_pos	[in,out] pointer to current offset to which the buffer is already used (in/out)
 * @param buf_len	[in]     length of the buffer
 * @param tag		[out]    tag extracted 
 * @param data		[out]    data extracted (pointer within buf)
 * @param data		[out]    length of data extracted
 *
 *
 * @return length of the tlv read, -1 if there was an error.
 */
size_t _muacc_read_tlv( 
	int fd,           	/**< [in]     file descriptor to read from */
 	char *buf,        	/**< [in]     pointer to buffer to put data */
	size_t *buf_pos,  	/**< [in,out] pointer to current offset to which the buffer is already used (in/out) */
	size_t buf_len,   	/**< [in]     length of the buffer */
 	muacc_tlv_t *tag, 	/**< [out]    tag extracted  */
 	void **data,      	/**< [out]    data extracted (pointer within buf) */
	size_t *data_len  	/**< [out]    length of data extracted */
);

	
/** make a deep copy of the addrinfo and encode in TLV
 *
 * @return length of the TLV or -1 on error
 */
size_t _muacc_push_addrinfo_tlv (
	char *buf,          		/**< [in]     buffer to copy TLV into */
	size_t *buf_pos,    		/**< [in,out] position of next free space in the buffer */
	size_t buf_len,     		/**< [in]     length of the buffer */
	muacc_tlv_t tag,    		/**< [in]     tag of the data */
	const struct addrinfo *ai0	/**< [in]     addrinfo sruct do encode */
);

/** decode an encoded socketaddr 
 *
 * @return size of the extracted struct
 */
size_t _muacc_extract_socketaddr_tlv(
	const char *data,           /**< [in]     buffer to extract from */
	size_t data_len,            /**< [in]     length of data */
	struct sockaddr **sa0       /**< [out]    pointer to extracted struct (will be allocated) */
);

/** decode an encoded addrinfo by deep copying 
 *
 * @return sum of the sizes of the extracted structs/stringd
 */
size_t _muacc_extract_addrinfo_tlv(
	const char *data,           /**< [in]     buffer to extract from */
	size_t data_len,            /**< [in]     length of data */
	struct addrinfo **ai0       /**< [out]    pointer to extracted struct (will be allocated) */
);

/** speak the TLV protocol as a client to make MAM update _ctx with her wisdom
 *
 * @return 0 on success, a negative number otherwise
 */
int _muacc_contact_mam (
	muacc_mam_action_t reason,	/**< [in]	reason for contacting */
	struct _muacc_ctx *_ctx		/**< [in]	context to be updated */
);

/** make the TLV client ready by establishing a connection to MAM
 *
 * @return 0 on success, a negative number otherwise
 */
int _connect_ctx_to_mam(struct _muacc_ctx *_ctx) ;

#endif
