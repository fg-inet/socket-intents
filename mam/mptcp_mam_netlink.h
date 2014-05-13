/** \file mptcp_mam_netlink.h
 *	Netlink helpers / family data structures
 */
#ifndef __MPTCP_MAM_NETLINK_H__
#define __MPTCP_MAM_NETLINK_H__

#include <netlink/netlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "mptcp_netlink_types.h"

/* attribute policy */
static struct nla_policy mam_mptcp_genl_policy[MAM_MPTCP_A_MAX + 1] = {
//libnl (userspace) ues a different name for null terminated strings...
#ifndef __KERNEL__
   [MAM_MPTCP_A_MSG]  = { .type = NLA_STRING },
#else
   [MAM_MPTCP_A_MSG]  = { .type = NLA_NUL_STRING },
#endif
   [MAM_MPTCP_A_IPV4] = { .type = NLA_U32 }
};

#endif /* __MPTCP_MAM_NETLINK_H__ */
