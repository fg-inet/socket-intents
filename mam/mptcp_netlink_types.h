/** \file mptcp_mam_netlink.h
 *	Netlink helpers / family data structures
 */
#ifndef __MPTCP_NETLINK_TYPES_H__
#define __MPTCP_NETLINK_TYPES_H__

/* commands */
enum
{
   MAM_MPTCP_C_UNSPEC,
   MAM_MPTCP_C_INIT,
   MAM_MPTCP_C_NEWFLOW,
   __MAM_MPTCP_C_MAX
};

/* attributes */
enum
{
   MAM_MPTCP_A_UNSPEC=0,
   MAM_MPTCP_A_MSG,
   MAM_MPTCP_A_IPV4,
   __MAM_MPTCP_A_MAX
};
#define MAM_MPTCP_A_MAX (__MAM_MPTCP_A_MAX - 1)


#endif /* __MPTCP_NETLINK_TYPES_H__ */
