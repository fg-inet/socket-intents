/** \file mptcp_mam_netlink.h
 *	Netlink helpers / family data structures
 */
#ifndef __MPTCP_NETLINK_PARSER_H__
#define __MPTCP_NETLINK_PARSER_H__

#include <netlink/netlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

unsigned short get_message_type(struct nlmsghdr *);
void parse_message(struct nlmsghdr*, int, struct nlattr**);
int new_v4_flow(struct nlmsghdr*, struct in_addr*);

#endif /* __MPTCP_NETLINK_PARSER_H__ */
