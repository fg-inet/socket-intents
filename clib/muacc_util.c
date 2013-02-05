#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>

#include "../config.h"

#include "muacc_util.h"
#include "muacc_ctx.h"


struct sockaddr *_muacc_clone_sockaddr(const struct sockaddr *src, size_t src_len)
{
	struct sockaddr *ret = NULL;

	if(src == NULL)
		return(NULL);

	if((ret = malloc(src_len)) == NULL)
		return NULL;

	memcpy(ret, src, src_len);

	return(ret);
}


char *_muacc_clone_string(const char *src)
 {
	 char* ret = NULL;

	 if ( src != NULL)
	 {
	 	size_t sl = strlen(src)+1;
	 	if( ( ret = malloc(sl) ) == NULL )
	 		return(NULL);
	 	memcpy( ret, src, sl);
	 	ret[sl] = 0x00;
	 }

	 return(ret);
 }


struct addrinfo *_muacc_clone_addrinfo(const struct addrinfo *src)
{
	struct addrinfo *res = NULL;
	struct addrinfo **cur = &res;

    const struct addrinfo *ai;

	if(src == NULL)
		return(NULL);

	for (ai = src; ai; ai = ai->ai_next)
	{
		/* allocate memory and copy */
		if( (*cur = malloc(sizeof(struct addrinfo))) == NULL )
			goto _muacc_clone_addrinfo_malloc_err;
		memcpy( *cur, ai, sizeof(struct addrinfo));

		if ( ai->ai_addr != NULL)
		{
			(*cur)->ai_addr = _muacc_clone_sockaddr(ai->ai_addr, ai->ai_addrlen);
			if((*cur)->ai_addr == NULL)
				goto _muacc_clone_addrinfo_malloc_err;
		}

		if ( ai->ai_canonname != NULL)
		{
			if( ( (*cur)->ai_canonname = _muacc_clone_string(ai->ai_canonname)) == NULL )
				goto _muacc_clone_addrinfo_malloc_err;
		}

		cur = &((*cur)->ai_next);

	}

	return res;

	_muacc_clone_addrinfo_malloc_err:
	fprintf(stderr, "%6d: _muacc_clone_addrinfo failed to allocate memory\n", (int) getpid());
	return NULL;

}


struct socketopt *_muacc_clone_socketopts(const struct socketopt *src)
{
	struct socketopt *ret = NULL;

	if (src == NULL)
		return NULL;

	if ((ret = malloc(sizeof(struct socketopt))) == NULL)
	{
		fprintf(stderr, "%6d: _muacc_clone_socketopts failed to allocate memory.\n", (int) getpid());
		return NULL;
	}
	else
	{
		memcpy(ret, src, sizeof(struct socketopt));

		const struct socketopt *srccurrent = src;
		struct socketopt *dstcurrent = ret;
		struct socketopt *new = NULL;

		while (srccurrent->next != NULL)
		{
			if ((new = malloc(sizeof(struct socketopt))) == NULL)
			{
				fprintf(stderr, "%6d: _muacc_clone_socketopts failed to allocate memory.\n", (int) getpid());
				return NULL;
			}
			else
			{
				dstcurrent-> next = new;
				memcpy(new, srccurrent->next, sizeof(struct socketopt));
				srccurrent = srccurrent->next;
				dstcurrent = dstcurrent->next;
			}
		}
	}

	return ret;
}


void _muacc_print_sockaddr(struct sockaddr *addr, size_t src_len)
{
	printf("{ ");
	if (addr == NULL)
		printf("NULL");
	else
	{
		if (addr->sa_family == AF_INET)
		{
			struct sockaddr_in *inaddr = (struct sockaddr_in *) addr;
			printf("sin_family = AF_INET, ");
			printf("sin_port = %d, ", ntohs(inaddr->sin_port));
			char ipaddr[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &inaddr->sin_addr, ipaddr, INET_ADDRSTRLEN) != NULL)
				printf("sin_addr = %s", ipaddr);
		}
		else if (addr->sa_family == AF_INET6)
		{
			struct sockaddr_in6 *inaddr = (struct sockaddr_in6 *) addr;
			printf("sin6_family = AF_INET6, ");
			printf("sin6_port = %d, ", ntohs(inaddr->sin6_port));
			printf("sin6_flowinfo = %d, ", inaddr->sin6_flowinfo);
			char ipaddr[INET6_ADDRSTRLEN];
			if (inet_ntop(AF_INET6, &inaddr->sin6_addr, ipaddr, INET6_ADDRSTRLEN) != NULL)
				printf("sin6_addr = %s, ", ipaddr);
			printf("sin6_scope_id = %d", inaddr->sin6_scope_id);
		}
		else if (addr->sa_family == AF_UNIX)
		{
			struct sockaddr_un *unaddr = (struct sockaddr_un *) addr;
			printf("sun_family = AF_UNIX, ");
			printf("sun_path = %s",unaddr->sun_path);
		}
		else
		{
			printf("sa_family = %d <unknown>", addr->sa_family);
		}
	}
	printf(" }");
}

void _muacc_print_addrinfo(struct addrinfo *addr)
{
	printf("{ ");
	if (addr == NULL)
		printf("NULL");
	else
	{
		struct addrinfo *current = addr;
		while (current != NULL)
		{
			printf("{ ");
			printf("ai_flags = %d, ", current->ai_flags);
			printf("ai_family = %d, ", current->ai_family);
			printf("ai_socktype = %d, ", current->ai_socktype);
			printf("ai_protocol = %d, ", current->ai_protocol);
			printf("ai_addr = ");
			_muacc_print_sockaddr(current->ai_addr, current->ai_addrlen);
			printf(", ");
			printf("ai_canonname = %s", current->ai_canonname);
			current = current->ai_next;
			printf(" }");
		}
	}
	printf(" }");
}

char *_muacc_get_socket_level (int level)
{
	struct protoent *p;

	switch(level)
	{
		case SOL_SOCKET:
			return "SOL_SOCKET";
		#ifdef USE_SO_INTENTS
		case SOL_INTENTS:
			return "SOL_INTENTS";
		#endif
		default:
			p = getprotobynumber(level);
			if(p == NULL)
				return "SOL_UNKNOWN";
			else
				return p->p_name;
	}
}

void _muacc_print_socket_options(struct socketopt *opts)
{
	printf("{ ");
	if (opts == NULL)
		printf("NULL");
	else
	{
		struct socketopt *current = opts;
		while (current != NULL)
		{
			printf("{ ");
			printf("level = %d (%s), ", current->level, _muacc_get_socket_level(current->level));
			printf("optname = %d, ", current->optname);
			if (current-> optval == NULL)
			{
				printf("optval = NULL, ");
			}
			else
			{
				int *value = current->optval;
				printf("optval = %d ", *value);
			}
			printf(" }");
			current = current->next;
		}
	}
	printf(" }");
}
