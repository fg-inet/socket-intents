/** \file mam_util.h
 *	Utilities for handling mam contexts and other data structures
 */
#ifndef __MAM_UTIL_H__
#define __MAM_UTIL_H__

#include "mam.h"

/** Helper to print a list of sockaddrs to a string */
size_t _mam_print_sockaddr_list(char *buf, size_t *buf_pos, size_t buf_len, const struct sockaddr_list *list);

/** Helper to print a list of prefixes to a string */
size_t _mam_print_prefix_list(char *buf, size_t *buf_pos, size_t buf_len, const struct src_prefix_list *prefixes);

/** Helper to print a mam context to a string */
size_t _mam_print_ctx(char *buf, size_t *buf_pos, size_t buf_len, const struct mam_context *ctx);

/** Helper that frees a source prefix list */
int _free_src_prefix_list (struct src_prefix_list *spfxl);

/** Helper that frees a context */
int _mam_free_ctx(struct mam_context *ctx);

/** Helper that fetches a function pointer from the handle of a policy module */
int _mam_fetch_policy_function(lt_dlhandle policy, const char *name, void **function);

#endif /* __MAM_UTIL_H__ */
