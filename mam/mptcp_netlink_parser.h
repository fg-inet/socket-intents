/** \file mptcp_mam_netlink.h
 *	Netlink helpers / family data structures
 */

#if !defined( __MPTCP_NETLINK_PARSER_H__ ) && defined( HAVE_LIBNL )
#define __MPTCP_NETLINK_PARSER_H__

#include <netlink/netlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

struct mptcp_flow_info {
	struct sockaddr_storage loc_addr;
	struct sockaddr_storage rem_addr;
	
	uint8_t loc_id;
	uint8_t rem_id;
	
	uint8_t loc_low_prio;
	uint8_t rem_low_prio;
	
	uint8_t rem_bitfield;
	uint16_t rem_port;
	
	uint64_t inode;
	uint32_t token;
};

unsigned short get_message_type(struct nlmsghdr *);
void parse_message(struct nlmsghdr*, int, struct nlattr**, struct nlattr**);
int new_flow(struct nlmsghdr *nhl, struct mptcp_flow_info *flow);
int new_iface(struct nlmsghdr*, struct in_addr*, struct in6_addr*);

#endif /* __MPTCP_NETLINK_PARSER_H__ */
