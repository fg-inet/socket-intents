/** \file policy_util.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "policy_util.h"
#include "mam/mam_util.h"

#include "dlog.h"

#include <time.h>

#ifndef MAM_POLICY_UTIL_NOISY_DEBUG0
#define MAM_POLICY_UTIL_NOISY_DEBUG0 0
#endif

#ifndef MAM_POLICY_UTIL_NOISY_DEBUG1
#define MAM_POLICY_UTIL_NOISY_DEBUG1 1
#endif

#ifndef MAM_POLICY_UTIL_NOISY_DEBUG2
#define MAM_POLICY_UTIL_NOISY_DEBUG2 0
#endif


int mampol_get_socketopt(struct socketopt *list, int level, int optname, socklen_t *optlen, void *optval)
{
	struct socketopt *current = list;
	int ret = -1;

	while (current != NULL)
	{
		if (current->level == level && current->optname == optname)
		{
			if (current->optval != NULL && optval != NULL)
			{
				*optlen = current->optlen;
				memcpy(optval, current->optval, current->optlen);
			}
			ret = 0;
		}
		current = current->next;
	}
	return ret;
}

void print_pfx_addr (gpointer element, gpointer data)
{
	if (!element)
		return;

	struct src_prefix_list *pfx = element;
	char addr_str[INET6_ADDRSTRLEN+1]; /** String for debug / error printing */

	/* Print first address of this prefix */
	if (pfx->family == AF_INET)
	{
		inet_ntop(AF_INET, &( ((struct sockaddr_in *) (pfx->if_addrs->addr))->sin_addr ), addr_str, sizeof(addr_str));
		printf("\n\t\t%s", addr_str);
	}
	else if (pfx->family == AF_INET6)
	{
		inet_ntop(AF_INET6, &( ((struct sockaddr_in6 *) (pfx->if_addrs->addr))->sin6_addr ), addr_str, sizeof(addr_str));
		printf("\n\t\t%s", addr_str);
	}

	/* Print policy info if available */
	if (pfx->policy_info != NULL)
		print_policy_info((void*) pfx->policy_info);
}

void make_v4v6_enabled_lists (GSList *baselist, GSList **v4list, GSList **v6list)
{
	printf("Configured addresses:");
	printf("\n\tAF_INET: ");
	filter_prefix_list (baselist, v4list, PFX_ENABLED, NULL, AF_INET, NULL);
	if (*v4list != NULL)
		g_slist_foreach(*v4list, &print_pfx_addr, NULL);
	else
		printf("\n\t\t(none)");

	printf("\n\tAF_INET6: ");
	filter_prefix_list (baselist, v6list, PFX_ENABLED, NULL, AF_INET6, NULL);
	if (*v6list != NULL)
		g_slist_foreach(*v6list, &print_pfx_addr, NULL);
	else
		printf("\n\t\t(none)");
}

void set_bind_sa(request_context_t *rctx, struct src_prefix_list *chosen, strbuf_t *sb)
{
	if(sb != NULL)
	{
		strbuf_printf(sb, "\n\tSet src=");
		_muacc_print_sockaddr(sb, chosen->if_addrs->addr, chosen->if_addrs->addr_len);
	}
	
	rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(chosen->if_addrs->addr, chosen->if_addrs->addr_len);
	rctx->ctx->bind_sa_suggested_len = chosen->if_addrs->addr_len;
	rctx->ctx->domain = chosen->family;
}

void _set_bind_sa(request_context_t *rctx, struct sockaddr *addr, strbuf_t *sb)
{
	strbuf_printf(sb, "\n\tSet src=");
	_muacc_print_sockaddr(sb, addr, sizeof(struct sockaddr));

	rctx->ctx->bind_sa_suggested = _muacc_clone_sockaddr(addr, sizeof(struct sockaddr));
	rctx->ctx->bind_sa_suggested_len = sizeof(struct sockaddr);
}


void print_addrinfo_response (struct addrinfo *res)
{
	strbuf_t sb;
	strbuf_init(&sb);

	struct addrinfo *item = res;
	while (item != NULL)
	{
		strbuf_printf(&sb, "\t");
		if (item->ai_family == AF_INET)
			_muacc_print_sockaddr(&sb, item->ai_addr, sizeof(struct sockaddr_in));
		else if (item->ai_family == AF_INET6)
			_muacc_print_sockaddr(&sb, item->ai_addr, sizeof(struct sockaddr_in6));

		strbuf_printf(&sb, "\n");
		item = item->ai_next;
	}

	printf("%s\n", strbuf_export(&sb));
	strbuf_release(&sb);
}

void *lookup_prefix_info(struct src_prefix_list *prefix, const void *key)
{
	if (prefix == NULL || key == NULL)
	{
		DLOG(MAM_POLICY_UTIL_NOISY_DEBUG1, "Warning: Tried to look up info for NULL prefix or NULL key\n");
		return NULL;
	}

	void *value = NULL;
	if (prefix->policy_set_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->policy_set_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in prefix policy_set_dict\n", (char* )key);
			return value;
		}
	}
	if (prefix->measure_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->measure_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in prefix measure_dict\n", (char *) key);
			return value;
		}
	}
	if (prefix->iface != NULL && prefix->iface->policy_set_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->iface->policy_set_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in iface policy_set_dict\n", (char *) key);
			return value;
		}
	}
	if (prefix->iface != NULL && prefix->iface->measure_dict != NULL)
	{
		value = g_hash_table_lookup(prefix->iface->measure_dict, key);
		if (value != NULL)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found key %s in iface measure_dict\n", (char *) key);
			return value;
		}
	}
	return value;
}

double lookup_value(struct src_prefix_list *prefix, const void *key, strbuf_t *sb)
{
    if (prefix == NULL)
        return 0;

    void *value = lookup_prefix_info(prefix, key);
    if (value == NULL) {
        strbuf_printf(sb, "\t\t%s: N/A,\t", key);
        return 0;
    }
    // Treating values as double by default
    double returnvalue = *(double *) value;

    if (strncmp(key, "num_conns", 9) == 0) {
        // Have to convert int to double
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Num_conns == %d\n", *(int *) value);
        returnvalue = *(int *) value;
    }

    if (returnvalue < EPSILON )
    {
        strbuf_printf(sb, "\t\t%s: 0,\t", key);
        return 0;
    }
    if ((DBL_MAX - returnvalue) < EPSILON)
    {
        strbuf_printf(sb, "\t\t%s: DBL_MAX -- returning 0,\t", key);
        return 0;
    }
    strbuf_printf(sb, "\t\t%s: %f,\t", key, returnvalue);
    return returnvalue;
}

int is_there_a_socket_on_prefix(struct socketlist *list, struct src_prefix_list *pfx)
{
    if (count_sockets_on_prefix(list, pfx, NULL) > 0)
        return 1;
    else
        return 0;
}

int count_sockets_on_prefix(struct socketlist *list, struct src_prefix_list *pfx, const char *logfile)
{
	strbuf_t sb;
	strbuf_init(&sb);

	int counter = 0;
	struct socketlist *current = list;

	while (current != NULL)
	{
		if (current->ctx == NULL)
		{
			continue;
		}

		// Find sockaddr of this socket
		struct sockaddr *addr = NULL;
		socklen_t addrlen = 0;

		if (current->ctx->bind_sa_suggested != NULL)
		{
			addr = current->ctx->bind_sa_suggested;
			addrlen = current->ctx->bind_sa_suggested_len;
		}
		else if (current->ctx->bind_sa_req != NULL)
		{
			addr = current->ctx->bind_sa_req;
			addrlen = current->ctx->bind_sa_req_len;
		}
		strbuf_printf(&sb, "Socket %d has address ", current->file);
		_muacc_print_sockaddr(&sb, addr, addrlen);

		if (addr != NULL && is_addr_in_prefix(addr, pfx) == 0)
		{
			strbuf_printf(&sb, " - matches prefix!\n");
            counter++;
            if (logfile != NULL)
                _muacc_logtofile(logfile, "%d-", current->file);
		}
		current = current->next;
	}
	strbuf_printf(&sb, "Reached end of function and no address for this prefix found\n");

	DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
	if (logfile != NULL)
		_muacc_logtofile(logfile, ",");
	return counter;
}

struct socketlist *find_socket_on_prefix(struct socketlist *sockets, struct src_prefix_list *pfx)
{
	while (sockets != NULL)
	{
		if (sockets->ctx == NULL)
		{
			continue;
		}

		struct sockaddr *addr = NULL;

		if (sockets->ctx->bind_sa_suggested != NULL)
		{
			addr = sockets->ctx->bind_sa_suggested;
		}
		else if (sockets->ctx->bind_sa_req != NULL)
		{
			addr = sockets->ctx->bind_sa_req;
		}

		if (addr != NULL && is_addr_in_prefix(addr, pfx) == 0 && !(sockets->flags & MUACC_SOCKET_IN_USE))
		{
			return sockets;
		}
		sockets = sockets->next;
	}
	return NULL;
}

void pick_sockets_on_prefix(request_context_t *rctx, struct src_prefix_list *bind_pfx)
{
	strbuf_t sb;
	strbuf_init(&sb);

	struct socketlist *current = rctx->sockets;
	struct socketlist *suggested = NULL;

	while (current != NULL)
	{
		if (current->ctx == NULL)
		{
			continue;
		}

		// Find sockaddr of this socket
		struct sockaddr *addr = NULL;
		socklen_t addrlen = 0;

		if (current->ctx->bind_sa_suggested != NULL)
		{
			addr = current->ctx->bind_sa_suggested;
			addrlen = current->ctx->bind_sa_suggested_len;
		}
		else if (current->ctx->bind_sa_req != NULL)
		{
			addr = current->ctx->bind_sa_req;
			addrlen = current->ctx->bind_sa_req_len;
		}
		strbuf_printf(&sb, "Socket %d has address ", current->file);
		_muacc_print_sockaddr(&sb, addr, addrlen);

		if (addr != NULL && is_addr_in_prefix(addr, bind_pfx) == 0 && !(current->flags & MUACC_SOCKET_IN_USE))
		{
			strbuf_printf(&sb, " - same subnet as prefix - suggesting it");
			if (suggested == NULL)
			{
				suggested = current;
				current = current->next;
				suggested->next = NULL;
			}
			else
			{
				// Append socket to list of suggested sockets
				struct socketlist *slist = suggested;
				while (slist->next != NULL)
					slist = slist->next;
				slist->next = current;
				current = current->next;
				slist->next->next = NULL;

			}
		}
		else
		{
			strbuf_printf(&sb, " - different subnet than prefix or likely in use - removing it");

			struct socketlist *slist_to_free = current;
			current = current->next;
			_muacc_free_ctx(slist_to_free->ctx);
			free(slist_to_free);
		}
	}

	rctx->sockets = suggested;

	DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "%s\n\n", strbuf_export(&sb));
	strbuf_release(&sb);
}

struct src_prefix_list *get_pfx_with_addr(request_context_t *rctx, struct sockaddr *addr)
{
	if (rctx == NULL || rctx->mctx == NULL || rctx->mctx->prefixes == NULL || addr == NULL)
		return NULL;

	GSList *current = rctx->mctx->prefixes;
	while (current != NULL)
	{
		struct src_prefix_list *currentpfx = (struct src_prefix_list *) current->data;
		if (currentpfx == NULL)
			continue;

		if (is_addr_in_prefix(addr, currentpfx) == 0)
		{
			DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Found prefix with the given address!\n");
			return currentpfx;
		}
		current = current->next;
	}
	DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "Did not find prefix with the given address!\n");
	return NULL;
}

double gettimestamp()
{
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	double measured_sec = current_time.tv_sec;
	double measured_usec = current_time.tv_usec;
	return (measured_sec + (measured_usec / 1000000));
}

void print_sockets(struct socketlist *sockets)
{
    if (sockets != NULL)
    {
        printf("[ %d", sockets->file);
        while (sockets->next != NULL)
        {
            printf(", %d", sockets->next->file);
            sockets = sockets->next;
        }
        printf(" ]");
    }
}

struct src_prefix_list *get_lowest_srtt_pfx(GSList *prefixes, const char *key)
{
    DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "trying to get lowest srtt from spl of length %d\n", g_slist_length(prefixes));
	struct src_prefix_list *lowest_srtt_pfx = NULL;
	double lowest_srtt = DBL_MAX;

    while (prefixes != NULL)
    {
		struct src_prefix_list *cur = prefixes->data;
		double *cur_srtt = lookup_prefix_info(cur, key);
		if (cur_srtt != NULL && *cur_srtt > EPSILON && *cur_srtt < lowest_srtt)
		{
			lowest_srtt = *cur_srtt;
			lowest_srtt_pfx = cur;
		}
        if (cur_srtt != NULL) {
            DLOG(MAM_POLICY_UTIL_NOISY_DEBUG2, "looking at %s: %s == %f\n", cur->if_name, key, *cur_srtt);
        }
        prefixes = prefixes->next;
    }
    if (lowest_srtt_pfx != NULL) {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "found lowest %s: %s == %f\n", lowest_srtt_pfx->if_name, key, lowest_srtt);
    } else {
        DLOG(MAM_POLICY_UTIL_NOISY_DEBUG0, "Did not find a lowest prefix with key %s!\n", key);
    }
	return lowest_srtt_pfx;
}

void insert_socket(int socketarray[], int socket)
{
	socketarray[socket] = 1;
}

int take_socket_from_array(int socketarray[], int socket)
{
	if (socketarray[socket] == 1)
	{
		// Socket was found in the array
		socketarray[socket] = 0;
		return 1;
	}
	else
	{
		// Return False - the socket was not found in the array
		return 0;
	}
}
