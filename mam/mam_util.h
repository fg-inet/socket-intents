/** \file mam_util.h
 *	Utilities for handling mam contexts and other data structures
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */
#ifndef __MAM_UTIL_H__
#define __MAM_UTIL_H__

#include "mam.h"

/** Helper to print a list of sockaddrs to a string */
void _mam_print_sockaddr_list(strbuf_t *sb, const struct sockaddr_list *list);

/** Helper to print a list of prefixes to a string */
void _mam_print_prefix_list(strbuf_t *sb, GSList *prefixes);

/** Helper to print a list of prefixes to a string */
void _mam_print_prefix(strbuf_t *sb, struct src_prefix_list *current);

/** Helper to print a list of interfaces to a string */
void _mam_print_iface_list(strbuf_t *sb, GSList *ifaces);

/** Helper to print interface properties e.g. whether to query load of wifi info */
void _mam_print_iface_additional_info(strbuf_t *sb, unsigned int additional_info);

/** Helper to print an interface to a string */
void _mam_print_iface(strbuf_t *sb, struct iface_list *current);

/** Helper to print a mam context to a string */
void _mam_print_ctx(strbuf_t *sb, const struct mam_context *ctx);

/** Helper that prints the measurement dictionary */
void _mam_print_measure_dict (gpointer key,  gpointer val, gpointer sb);

/** Helper that frees a source prefix list - to be called using g_slist_free_full */
void _free_src_prefix_list (gpointer data);

/** Helper that frees an iface list item - to be called using g_slist_free_full */
void _free_iface_list (gpointer data);

void _free_client_list (gpointer data);
void _free_socket_list (gpointer data);

/** Helper that frees a context */
int _mam_free_ctx(struct mam_context *ctx);

/** Helper that fetches a function pointer from the handle of a policy module */
int _mam_fetch_policy_function(lt_dlhandle policy, const char *name, void **function);

#define _muacc_proc_tlv_event_too_short	-1
#define _muacc_proc_tlv_event_eof		0
/** try to read a TLV from an libevent2 evbuffer
 *
 * @return number of bytes processed, 0 if last TLV was EOF, -1 if buffer was too short
 */
int _muacc_proc_tlv_event(
	request_context_t *ctx		/**< [in]	  ctx to extract data to */
);

/** send context via libevent evbuffer
 *
 * @return 0 on success, -1 if there was an error.
 */
int _muacc_send_ctx_event(request_context_t *ctx, muacc_mam_action_t reason);

/** helper to print a prefix list flags into a string
 *
 */
void _mam_print_prefix_list_flags(strbuf_t *sb, unsigned int	pfx_flags);

/** helper that tries to call a policy function. If it fails, it simply tries to send back the context
 *
 * @return 0 if callback was successfully invoked, -1 if it failed
 */
int _mam_callback_or_fail(request_context_t *ctx, const char *function, unsigned int calls_performed_flag, muacc_mam_action_t action_if_fail);

/** Helper to clear prefix flags */
void _mam_clear_prefix_flags(void *pfx, void *data);

/** check whether two ipv4 addresses are in the same subnet 
 *
 * Returns 0 if they are in the same subnet 
 */
int _cmp_in_addr_with_mask(
	struct in_addr *a,		
	struct in_addr *b,
	struct in_addr *mask	/**< the subnet mask */
);

/** check whether two ipv6 addresses are in the same subnet
 *
 * Returns 0 if they are in the same subnet 
 */
int _cmp_in6_addr_with_mask(
	struct in6_addr *a,		
	struct in6_addr *b,
	struct in6_addr *mask	/**< the subnet mask */
);

/* Check if a sockaddr in in the same subnet as a given prefix) */
int is_addr_in_prefix(struct sockaddr *addr, struct src_prefix_list *pfx);
#endif /* __MAM_UTIL_H__ */
