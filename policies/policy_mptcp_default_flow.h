#include "policy.h"
#include "policy_util.h"
#include "../clib/muacc.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../mam/mptcp_netlink_parser.h"
#include "../mam/mam_netlink.h"

/** Policy-specific per-prefix data structure that contains additional information */
struct default_flow_info {
	int is_enabled_for_flow;
	int is_default;
};

void establish_new_flow(gpointer elem, gpointer ip);
void __g_slist_foreach(gpointer key, gpointer value, gpointer user);
void __g_hash_table_foreach(gpointer elem, gpointer ip);
int on_config_request(mam_context_t *mctx, char* config);
gint compare_inode_in_struct(gpointer list_data,  gpointer user_data);