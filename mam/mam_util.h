/** \file mam_util.h
 *	Utilities for handling mam contexts and other data structures
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

/** Helper to print a mam context to a string */
void _mam_print_ctx(strbuf_t *sb, const struct mam_context *ctx);

/** Helper that frees a source prefix list - to be called using g_slist_free_full */
void _free_src_prefix_list (gpointer data);

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

#endif /* __MAM_UTIL_H__ */
