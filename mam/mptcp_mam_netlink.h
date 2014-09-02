/** \file mptcp_mam_netlink.h
 *	Netlink helpers / family data structures
 */
#ifndef __MPTCP_MAM_NETLINK_H__
#define __MPTCP_MAM_NETLINK_H__

#ifndef __KERNEL__
#include <netlink/netlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#else
#include <linux/netlink.h>
#include <net/genetlink.h>
#endif

#include "mptcp_netlink_types.h"

/* attribute policy */
static struct nla_policy mam_mptcp_genl_policy[MAM_MPTCP_A_MAX + 1] = {
//libnl (userspace) ues a different names...
#ifndef __KERNEL__
	[MAM_MPTCP_A_STRMSG]  = { .type = NLA_STRING,
							  .maxlen = MAM_MPTCP_A_STRMSG_MAXLEN },
	[MAM_MPTCP_A_IPV6] = { .type = NLA_UNSPEC},
	[MAM_MPTCP_A_IPV6_LOC] = { .type = NLA_UNSPEC},
	[MAM_MPTCP_A_IPV6_REM] = { .type = NLA_UNSPEC},
#else
	[MAM_MPTCP_A_STRMSG]  = { .type = NLA_NUL_STRING,
							  .len = MAM_MPTCP_A_STRMSG_MAXLEN },
	[MAM_MPTCP_A_IPV6] = { .type = NLA_BINARY,
						   .len = sizeof(struct in6_addr) },
	[MAM_MPTCP_A_IPV6_LOC] = { .type = NLA_BINARY,
						   .len = sizeof(struct in6_addr) },
	[MAM_MPTCP_A_IPV6_REM] = { .type = NLA_BINARY,
						   .len = sizeof(struct in6_addr) },
#endif
	[MAM_MPTCP_A_IPV4_LOC] = { .type = NLA_U32 },
	[MAM_MPTCP_A_LOC_ID] = { .type = NLA_U8 },
	[MAM_MPTCP_A_LOC_PRIO] = { .type = NLA_U8 },
	
	[MAM_MPTCP_A_IPV4_REM] = { .type = NLA_U32 },
	[MAM_MPTCP_A_REM_ID] = { .type = NLA_U8 },
	[MAM_MPTCP_A_REM_PRIO] = { .type = NLA_U8 },
	[MAM_MPTCP_A_REM_BIT] = { .type = NLA_U8 },
	[MAM_MPTCP_A_REM_PORT] = { .type = NLA_U16 },
	
	[MAM_MPTCP_A_INODE] = { .type = NLA_U64 },
	[MAM_MPTCP_A_TOKEN] = { .type = NLA_U32 },
	
	[MAM_MPTCP_A_OK] = { .type = NLA_FLAG },
	[MAM_MPTCP_A_NOT_OK] = { .type = NLA_FLAG },

	[MAM_MPTCP_A_IS_V6] = { .type = NLA_FLAG }
};

#endif /* __MPTCP_MAM_NETLINK_H__ */
