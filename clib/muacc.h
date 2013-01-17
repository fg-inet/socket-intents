#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef _MUACC_CTX_
#define _MUACC_CTX_

#define MUACC_TLV_LEN 2048

typedef struct muacc_context 
{
	struct _muacc_ctx *ctx;
} muacc_context_t;
	
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
	remote_sa_res,     		/* remote address choosen */	
} muacc_tlv_t;
	
typedef enum 
{
	muacc_action_connect,
	muacc_action_getaddrinfo,
	muacc_action_setsocketopt
} muacc_mam_action_t;

int muacc_init_context(struct muacc_context *ctx);
int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src);
int muacc_retain_context(struct muacc_context *ctx);
	int muacc_release_context(struct muacc_context *ctx);

int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res);
int muacc_setsockopt(struct muacc_context *ctx, 
        int socket, int level, int option_name,
        const void *option_value, socklen_t option_len);
int muacc_connect(struct muacc_context *ctx,
	    int socket, struct sockaddr *address, socklen_t address_len);

#endif