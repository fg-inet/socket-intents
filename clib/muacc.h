#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define _MUACC_CTX_

typedef struct muacc_context {
	struct _muacc_ctx *ctx;
} muacc_context_t;

struct _muacc_ctx {
	int flags;
	int usage;
	int msock;
	struct sockaddr *bind_sa;
	socklen_t bind_sa_len;
	struct sockaddr *remote_sa;
	socklen_t remote_sa_len;
	char *remote_hostname;
	struct addrinfo	*remote_addrinfo;	
};

int muacc_init_context(struct muacc_context *ctx);
int muacc_clone_context(struct muacc_context *dst, struct muacc_context *src);
int muacc_release_context(struct muacc_context *ctx);

int muacc_getaddrinfo(struct muacc_context *ctx,
		const char *hostname, const char *servname,
		const struct addrinfo *hints, struct addrinfo **res);
int muacc_setsockopt(struct muacc_context *ctx, 
        int socket, int level, int option_name,
        const void *option_value, socklen_t option_len);
int muacc_connect(struct muacc_context *ctx,
	    int socket, struct sockaddr *address, socklen_t address_len);