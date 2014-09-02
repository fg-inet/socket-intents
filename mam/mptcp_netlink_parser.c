/**
 * \file mptcp_netlink_parser.c
 *
 */

#include "lib/dlog.h"
#include "mam_netlink.h"
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
	else
		printf("Parsed message attributes\n");
}

int new_iface(struct nlmsghdr *nhl, struct in_addr* addr_v4, struct in6_addr* addr_v6)
{
	struct nlattr *attrs[MAM_MPTCP_A_MAX+1];
	
	parse_message(nhl, MAM_MPTCP_C_NEWIFACE, attrs, NULL);

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
	}

	perror("Message did not contain ip attributes!\n");
	return -1;
}

int new_v4_flow(struct nlmsghdr *nhl, struct mptcp_flow_info *flow)
{
	struct nlattr *attrs[MAM_MPTCP_A_MAX+1];
	
	parse_message(nhl, MAM_MPTCP_C_NEWFLOW, attrs, NULL);
	
	printf("parsed message!\n");

	if (flow)
	{
		if (attrs[MAM_MPTCP_A_IPV4_LOC])
			flow->loc_addr = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_LOC]);
		else
		{
			printf("no loc \n");
			return -1;
		}
			
		if (attrs[MAM_MPTCP_A_IPV4_LOC_ID])
			flow->loc_id = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_LOC_ID]);
		else
		{
			printf("no loc id\n");
			return -1;
		}
		
		if (attrs[MAM_MPTCP_A_IPV4_LOC_PRIO])
			flow->loc_low_prio = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_LOC_PRIO]);
		else
		{
			printf("no loc prio \n");
			return -1;
		}
		
		if (attrs[MAM_MPTCP_A_IPV4_REM])
			flow->rem_addr = nla_get_u32(attrs[MAM_MPTCP_A_IPV4_REM]);
		else
		{
			printf("no rem\n");
			return -1;
		}
			
		if (attrs[MAM_MPTCP_A_IPV4_REM_ID])
			flow->rem_id = nla_get_u8(attrs[MAM_MPTCP_A_IPV4_REM_ID]);
		else
		{
			printf("no rem id\n");
			return -1;
		}
			
		if (attrs[MAM_MPTCP_A_IPV4_REM_BIT])
			flow->rem_bitfield = nla_get_u8(attrs[MAM_MPTCP_A_IPV4_REM_BIT]);
		else
		{
			printf("no rem bit\n");
			return -1;
		}
			
	
		if (attrs[MAM_MPTCP_A_IPV4_REM_PORT])
			flow->rem_port = nla_get_u16(attrs[MAM_MPTCP_A_IPV4_REM_PORT]);
		else
		{
			printf("no rem port\n");
			return -1;
		}
			
		if (attrs[MAM_MPTCP_A_INODE])
			flow->inode = nla_get_u64(attrs[MAM_MPTCP_A_INODE]);
		else
		{
			printf("no inode\n");
			return -1;
		}
		
		if (attrs[MAM_MPTCP_A_TOKEN])
			flow->token = nla_get_u32(attrs[MAM_MPTCP_A_TOKEN]);
		else
		{
			printf("no token \n");
			return -1;
		}
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

