/**
 * \file netlink_monitor.c
 *
 */

#include "../mam/mptcp_netlink_types.h"
#include "../mam/mptcp_netlink_parser.h"
#include <unistd.h>

struct nl_sock *netlink_sk;
int family;

int netlink_readcb(struct nl_msg *msg, void *dummy);


int netlink_readcb(struct nl_msg *msg, void *dummy)
{
	struct in_addr ipv4;
	struct mptcp_rem_loc rem_loc;
	
	uint32_t inode;
	uint32_t token;
	struct in6_addr ipv6;
	struct nl_msg *msg_out;
	void *hdr;
	int err;
	
	printf("read callback called!\n");
	
	switch(get_message_type(nlmsg_hdr(msg)))
	{
		case MAM_MPTCP_C_NEWFLOW:
			printf("waiting 3 second before answering\n");
			//usleep(500000);
			sleep(3);
			printf("answering now!\n");
			new_v4_flow(nlmsg_hdr(msg), &rem_loc, &inode, &token);
			
			msg_out = nlmsg_alloc();
			
			if (msg_out == NULL)
				perror("Could not alloc netlink message\n");
			
			hdr = genlmsg_put(msg_out, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0, MAM_MPTCP_C_NEWFLOW, 1);
			
			if (hdr == NULL)
				perror("Header of netlink message not written.\n");
			
			if (nla_put_flag(msg_out, MAM_MPTCP_A_OK) < 0)
				perror("Could not add attribute to new flow response message\n");
				
			if (nla_put_u32(msg_out, MAM_MPTCP_A_INODE, inode) < 0)
				perror("Could not add attribute to new flow response message\n");
				
			if (nla_put_u32(msg_out, MAM_MPTCP_A_TOKEN, token) < 0)
				perror("Could not add attribute to new flow response message\n");
				
			if (nla_put_u32(msg_out, MAM_MPTCP_A_IPV4_LOC, rem_loc.loc_addr) < 0)
				perror("Could not add attribute to new flow response message\n");
			if (nla_put_u8(msg_out, MAM_MPTCP_A_IPV4_LOC_ID, rem_loc.loc_id) < 0)
				perror("Could not add attribute to new flow response message\n");
			if (nla_put_u8(msg_out, MAM_MPTCP_A_IPV4_LOC_PRIO, rem_loc.loc_low_prio) < 0)
				perror("Could not add attribute to new flow response message\n");
				
			if (nla_put_u32(msg_out, MAM_MPTCP_A_IPV4_REM, rem_loc.rem_addr) < 0)
				perror("Could not add attribute to new flow response message\n");
			if (nla_put_u8(msg_out, MAM_MPTCP_A_IPV4_REM_ID, rem_loc.rem_id) < 0)
				perror("Could not add attribute to new flow response message\n");
			if (nla_put_u8(msg_out, MAM_MPTCP_A_IPV4_REM_PRIO, rem_loc.rem_low_prio) < 0)
				perror("Could not add attribute to new flow response message\n");
			if (nla_put_u8(msg_out, MAM_MPTCP_A_IPV4_REM_BIT, rem_loc.rem_bitfield) < 0)
				perror("Could not add attribute to new flow response message\n");
			if (nla_put_u8(msg_out, MAM_MPTCP_A_IPV4_REM_RETR_BIT, rem_loc.rem_retry_bitfield) < 0)
				perror("Could not add attribute to new flow response message\n");
			if (nla_put_u16(msg_out, MAM_MPTCP_A_IPV4_REM_PORT, rem_loc.rem_port) < 0)
				perror("Could not add attribute to new flow response message\n");
			
			if((err = nl_send_auto(netlink_sk, msg_out)) < 0)
				perror("Could not send netlink message\n");
			else
				printf("sent message out\n");

			nlmsg_free(msg_out);
			
			break;
			
		case MAM_MPTCP_C_NEWIFACE:
			//printf("new message of type interface\n");
			new_iface(nlmsg_hdr(msg), &ipv4, &ipv6);
			//printf("newiface: ipv4: %u\n", ipv4.s_addr);
			//printf("newiface: addr: %u\n", ipv4.s_addr);
			break;
	}
	return 0;
}

int main(void)
{
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
	if (group <= 0)
	{
		perror("MAM_MPTCP netlink group not found\n");
		return -1;
	}
	else
		printf("Netlink group-id: %u\n", group);
	
	nl_socket_set_nonblocking(netlink_sk);
	
	//TODO check if true
	//currently there is no check implemented
	nl_socket_disable_seq_check(netlink_sk);

	nl_socket_add_membership(netlink_sk, group);

	nl_socket_modify_cb(netlink_sk, NL_CB_VALID, NL_CB_CUSTOM, netlink_readcb, NULL);	

	//TODO CRITICAL: no graceful shutdown possible...
	while (1)
	{
        nl_recvmsgs_default(netlink_sk);
		usleep(1000);
	}
			
	nl_close(netlink_sk);
	nl_socket_free(netlink_sk);
}

