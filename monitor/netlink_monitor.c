/**
 * \file netlink_monitor.c
 *
 */

#include "../mam/mptcp_netlink_types.h"
#include "../mam/mptcp_netlink_parser.h"

struct nl_sock *netlink_sk;

int netlink_readcb(struct nl_msg *msg, void *dummy);

int netlink_readcb(struct nl_msg *msg, void *dummy)
{
	struct in_addr ipv4;
	
	switch(get_message_type(nlmsg_hdr(msg)))
	{
		case MAM_MPTCP_C_NEWFLOW:
			new_v4_flow(nlmsg_hdr(msg), &ipv4);
			printf("newflow: addr: %u\n", ipv4.s_addr);
			break;
	}
	return 0;
}

int main(void)
{
	int family;
	uint32_t group;

	netlink_sk = nl_socket_alloc();
	genl_connect(netlink_sk);

	family = genl_ctrl_resolve(netlink_sk, "MAM_MPTCP");
	if (family == 0)
	{
		perror("MAM_MPTCP netlink family not found\n");
		return -1;
	}

	group = genl_ctrl_resolve_grp(netlink_sk, "MAM_MPTCP", "MAM_MPTCP");
	if (group == 0)
	{
		perror("MAM_MPTCP netlink group not found\n");
		return -1;
	}
	else
		printf("Netlink group-id: %u\n", group);
	
	nl_socket_set_nonblocking(netlink_sk);
	//currently there is no check implemented
	nl_socket_disable_seq_check(netlink_sk);

	nl_socket_add_membership(netlink_sk, group);

	nl_socket_modify_cb(netlink_sk, NL_CB_VALID, NL_CB_CUSTOM, netlink_readcb, NULL);	

	//TODO CRITICAL: no graceful shutdown possible...
	while (1)
        nl_recvmsgs_default(netlink_sk);
			
	nl_close(netlink_sk);
	nl_socket_free(netlink_sk);
}

