#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>

#include "../config.h"

#include "muacc_types.h"
#include "muacc_util.h"
#include "muacc_ctx.h"

#ifdef USE_SO_INTENTS
#include "../libintents/libintents.h"
#endif

#ifndef CLIB_UTIL_NOISY_DEBUG
#define CLIB_UTIL_NOISY_DEBUG 0
#endif


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


			dstcurrent-> next = new;
			memcpy(new, srccurrent->next, sizeof(struct socketopt));

			if(srccurrent->next->optlen > 0 && srccurrent->next->optval != NULL)
			{
				if ((new->optval = malloc(sizeof(struct socketopt))) == NULL)
				{
					fprintf(stderr, "%6d: _muacc_clone_socketopts failed to allocate memory.\n", (int) getpid());
					return NULL;
				}
				memcpy(new->optval, srccurrent->next->optval, srccurrent->next->optlen);
			}

			srccurrent = srccurrent->next;
			dstcurrent = dstcurrent->next;
		}
	}

	return ret;
}

void _muacc_free_socketopts(struct socketopt *so)
{
	struct socketopt *next = so;

	while(next != NULL)
	{
		struct socketopt *last = next;
		next = last->next;

		if(last->optlen > 0 && last->optval != NULL)
			free(last->optval);

		free(last);
	}

}



size_t _muacc_print_sockaddr(char *buf, size_t *buf_pos, size_t buf_len, const struct sockaddr *addr, size_t src_len)
{
	size_t old_pos = *buf_pos;
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "{ ");
	if (addr == NULL)
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "NULL");
	else
	{
		if (addr->sa_family == AF_INET)
		{
			struct sockaddr_in *inaddr = (struct sockaddr_in *) addr;
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin_family = AF_INET, ");
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin_port = %d, ", ntohs(inaddr->sin_port));
			char ipaddr[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &inaddr->sin_addr, ipaddr, INET_ADDRSTRLEN) != NULL)
				*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin_addr = %s", ipaddr);
		}
		else if (addr->sa_family == AF_INET6)
		{
			struct sockaddr_in6 *inaddr = (struct sockaddr_in6 *) addr;
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin6_family = AF_INET6, ");
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin6_port = %d, ", ntohs(inaddr->sin6_port));
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin6_flowinfo = %d, ", inaddr->sin6_flowinfo);
			char ipaddr[INET6_ADDRSTRLEN];
			if (inet_ntop(AF_INET6, &inaddr->sin6_addr, ipaddr, INET6_ADDRSTRLEN) != NULL)
				*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin6_addr = %s, ", ipaddr);
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sin6_scope_id = %d", inaddr->sin6_scope_id);
		}
		else if (addr->sa_family == AF_UNIX)
		{
			struct sockaddr_un *unaddr = (struct sockaddr_un *) addr;
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sun_family = AF_UNIX, ");
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sun_path = %s",unaddr->sun_path);
		}
		else
		{
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "sa_family = %d <unknown>", addr->sa_family);
		}
	}
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  " }");

	return(*buf_pos - old_pos);
}

size_t _muacc_print_addrinfo(char *buf, size_t *buf_pos, size_t buf_len, const struct addrinfo *addr)
{
	size_t old_pos = *buf_pos;
	const struct addrinfo *current = addr;

	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "{ ");

	while (current != NULL)
	{
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "{ ");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "ai_flags = %d, ", current->ai_flags);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "ai_family = %d, ", current->ai_family);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "ai_socktype = %d, ", current->ai_socktype);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "ai_protocol = %d, ", current->ai_protocol);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "ai_addr = ");
		_muacc_print_sockaddr( buf, buf_pos, buf_len, current->ai_addr, current->ai_addrlen);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  ", ");
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "ai_canonname = %s", current->ai_canonname);
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  " }, ");
		current = current->ai_next;
	}

	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "NULL }");

	return(*buf_pos - old_pos);
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

void _muacc_print_socket_option_list(const struct socketopt *opts)
{
	char buf[4096];
	size_t buf_len = 4096;
	size_t buf_pos = 0;

	_muacc_print_socket_options(buf, &buf_pos, buf_len, opts);
	printf("%s\n", buf);
}

size_t _muacc_print_socket_options(char *buf, size_t *buf_pos, size_t buf_len, const struct socketopt *opts)
{
	size_t old_pos = *buf_pos;

	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "{ ");
	if (opts == NULL)
		*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "NULL");
	else
	{
		const struct socketopt *current = opts;
		while (current != NULL)
		{
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "{ ");
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "level = %d (%s), ", current->level, _muacc_get_socket_level(current->level));
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "optname = %d, ", current->optname);
			if (current-> optval == NULL)
			{
				*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "optval = NULL, ");
			}
			else
			{
				int *value = current->optval;
				*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  "optval = %d ", *value);
			}
			*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  " }");
			current = current->next;
		}
	}
	*buf_pos += snprintf( (buf + *buf_pos), (buf_len - *buf_pos),  " }");

	return(*buf_pos - old_pos);
}
