/**
 * \file mptcp_netlink_parser.c
 *
 */

#include "lib/dlog.h"
#include "mptcp_netlink_types.h"
#include "mptcp_mam_netlink.h"
#include "mptcp_netlink_parser.h"
#include <arpa/inet.h>


#ifndef NETLINK_PARSER_NOISY_DEBUG0
#define NETLINK_PARSER_NOISY_DEBUG0 1
#endif

#ifndef NETLINK_PARSER_NOISY_DEBUG1
#define NETLINK_PARSER_NOISY_DEBUG1 1
#endif

#ifndef NETLINK_PARSER_NOISY_DEBUG2
#define NETLINK_PARSER_NOISY_DEBUG2 1
#endif


#if (NETLINK_PARSER_NOISY_DEBUG2 == 1)
char *commands[__MAM_MPTCP_C_MAX] = {"MAM_MPTCP_A_UNSPEC", "MAM_MPTCP_C_INIT", "MAM_MPTCP_C_NEWFLOW", "MAM_MPTCP_C_NEWIFACE", }; // "MAM_MPTCP_C_REMIFACE", "MAM_MPTCP_C_INFOMSG"};
#endif

unsigned short get_message_type(struct nlmsghdr *nlh)
{
	return genlmsg_hdr(nlh)->cmd;
}

void parse_message(struct nlmsghdr *nlh, int type, struct nlattr **attrs, struct nlattr **nested)
{
	int i = 0;
	if (genlmsg_hdr(nlh)->cmd == type)
	{
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "New Message. Type: %s\n", commands[type]);
	}
	else
	{
		perror("Message is not of given type.\n");
		return;
	}
	
	if(genlmsg_parse(nlh, 0, attrs, MAM_MPTCP_A_MAX, mam_mptcp_genl_policy) < 0)
		perror("Could not parse netlink message attributes!\n");
	
	if (nested)
		for (i = 0; i < MAM_MPTCP_A_MAX; ++i)
			if (attrs[i])
				if (attrs[i]->nla_type == NLA_NESTED)
					if (nla_parse_nested(nested, MAM_MPTCP_N_A_MAX, attrs[i], mam_mptcp_genl_nested_policy) < 0)
						perror("Could not parse netlink message nested attributes.\n");
	
}

int new_iface(struct nlmsghdr *nhl, struct in_addr* addr_v4, struct in6_addr* addr_v6)
{
	struct nlattr *attrs[MAM_MPTCP_A_MAX+1];
	struct nlattr *nested[MAM_MPTCP_N_A_MAX+1];
	
	parse_message(nhl, MAM_MPTCP_C_NEWIFACE, attrs, nested);

	if (attrs[MAM_MPTCP_A_IPV4])
	{
		if (addr_v4)
			addr_v4->s_addr = nla_get_u32(attrs[MAM_MPTCP_A_IPV4]);
			
		struct in_addr ia;
		ia.s_addr = nla_get_u32(attrs[MAM_MPTCP_A_IPV4]);
		
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "IP: %s\n\n", inet_ntoa(ia));
		return 0;
	}
	else
	if (attrs[MAM_MPTCP_A_IPV6])
	{
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "new-interface v6 message\n");
	
		if (nested[MAM_MPTCP_N_A_IPV6_0] && nested[MAM_MPTCP_N_A_IPV6_1] && nested[MAM_MPTCP_N_A_IPV6_2] && nested[MAM_MPTCP_N_A_IPV6_3])
		{
			
			DLOG(NETLINK_PARSER_NOISY_DEBUG2, "Content of new-interface v6 message: %04x:%04x:%04x:%04x\n\n", nla_get_u32(nested[MAM_MPTCP_N_A_IPV6_0]),
																											nla_get_u32(nested[MAM_MPTCP_N_A_IPV6_1]),
																											nla_get_u32(nested[MAM_MPTCP_N_A_IPV6_2]),
																											nla_get_u32(nested[MAM_MPTCP_N_A_IPV6_3]));
			return 0;
		}
	}

	perror("Message did not contain ip attributes!\n");
	return -1;
}

int new_v4_flow(struct nlmsghdr *nhl, struct mptcp_flow_info *flow)
{
	struct nlattr *attrs[MAM_MPTCP_A_MAX+1];
	
	parse_message(nhl, MAM_MPTCP_C_NEWFLOW, attrs, NULL);

	if (attrs[MAM_MPTCP_A_IPV4_LOC])
	{
		if (flow)
		{
			flow->loc_addr = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_LOC]);
			flow->loc_id = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_LOC_ID]);
			flow->loc_low_prio = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_LOC_PRIO]);
			
			flow->rem_addr = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_REM]);
			flow->rem_id = nla_get_u8(attrs[MAM_MPTCP_A_IPV4_REM_ID]);
			flow->rem_bitfield = nla_get_u8(attrs[MAM_MPTCP_A_IPV4_REM_BIT]);
			flow->rem_retry_bitfield = nla_get_u8(attrs[MAM_MPTCP_A_IPV4_REM_RETR_BIT]);
			flow->rem_port = nla_get_u16(attrs[MAM_MPTCP_A_IPV4_REM_PORT]);
			
			flow->inode = nla_get_u64(attrs[MAM_MPTCP_A_INODE]);
			flow->token = nla_get_u32(attrs[MAM_MPTCP_A_TOKEN]);
		}
			
		struct in_addr ia;
		ia.s_addr = flow->loc_addr;
		
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "local IP : %s\n", inet_ntoa(ia));
		ia.s_addr = flow->rem_addr;
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "remote IP: %s\n", inet_ntoa(ia));
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "INODE    : %08x:%08x\n\n", (uint32_t)(nla_get_u64(attrs[MAM_MPTCP_A_INODE]) >> 32),
																	  (uint32_t)(nla_get_u64(attrs[MAM_MPTCP_A_INODE]) & 0xFFFFFFFF));
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "TOKEN    : %08x\n\n", nla_get_u32(attrs[MAM_MPTCP_A_TOKEN]));
		
		return 0;
	}
	else
	{
		perror("Message did not contain ipv4 attribute!\n");
		return -1;
	}
}
