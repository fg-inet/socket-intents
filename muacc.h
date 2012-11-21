#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef struct muacc_ctx {
	struct sockaddr *local_sa;
	socklen_t local_sa_len;
	struct sockaddr *remote_sa;
	socklen_t remote_sa_len;
	char *remote_hostname;		
} muacc_ctx_t;

