/**
 * \file mptcp_netlink_parser.c
 *
 */

#include "lib/dlog.h"
#include "mptcp_netlink_types.h"
#include "mptcp_mam_netlink.h"
#include "mptcp_netlink_parser.h"


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
char *commands[__MAM_MPTCP_C_MAX] = {"MAM_MPTCP_A_UNSPEC", "MAM_MPTCP_C_INIT", "MAM_MPTCP_C_NEWFLOW"};
#endif

unsigned short get_message_type(struct nlmsghdr *nlh)
{
	return genlmsg_hdr(nlh)->cmd;
}

void parse_message(struct nlmsghdr *nlh, int type, struct nlattr **attrs)
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
}


int new_v4_flow(struct nlmsghdr *nhl, struct in_addr* addr)
{
	struct nlattr *attrs[MAM_MPTCP_A_MAX+1];
	
	parse_message(nhl, MAM_MPTCP_C_NEWFLOW, attrs);

	if (attrs[MAM_MPTCP_A_IPV4])
	{
		if (addr)
			addr->s_addr = nla_get_u32(attrs[MAM_MPTCP_A_IPV4]);
		DLOG(NETLINK_PARSER_NOISY_DEBUG2, "Content of newflow message: %u\n", nla_get_u32(attrs[MAM_MPTCP_A_IPV4]));
		return 0;
	}
	else
	{
		perror("Message did not contain ipv4 attribute!\n");
		return -1;
	}
}
