/**
 * \file mam_netlink.c
 *
 */

#include <netlink/netlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "mam.h"
#include "mam_util.h"
#include "mam_netlink.h"
#include "mptcp_netlink_types.h"
#include "mptcp_netlink_parser.h"


#ifndef MAM_NETLINK_NOISY_DEBUG0
#define MAM_NETLINK_NOISY_DEBUG0 1
#endif

#ifndef MAM_NETLINK_NOISY_DEBUG1
#define MAM_NETLINK_NOISY_DEBUG1 1
#endif

#ifndef MAM_NETLINK_NOISY_DEBUG2
#define MAM_NETLINK_NOISY_DEBUG2 0
#endif

extern struct mam_context *global_mctx;

struct nl_sock *netlink_sk;
int family;

void netlink_readcb(struct bufferevent *bev, void *dummy)
{
	struct evbuffer *in;
	struct nlmsghdr *nhl;
	unsigned char *buf = NULL;
	size_t len;
	int (*new_subflow_function)() = NULL;	
	struct mptcp_flow_info flow;

	in = bufferevent_get_input(bev);
	len = evbuffer_get_length(in);
	buf = evbuffer_pullup(in, len);
	
	nhl = (struct nlmsghdr *) buf;
	
	switch(get_message_type(nhl))
	{
		case MAM_MPTCP_C_NEWFLOW:
			new_flow(nhl, &flow);
						
			if (_mam_fetch_policy_function(global_mctx->policy, "on_new_subflow_request", (void **)&new_subflow_function) == 0)
			{
				if (new_subflow_function(global_mctx, &flow))
				{
					create_new_flow(&flow);
				}
			}
			else
			{
				DLOG(MAM_NETLINK_NOISY_DEBUG2, "Policy-function: on_new_subflow_request could not be called!");
			}
			break;
			
		case MAM_MPTCP_C_NEWIFACE:
			new_iface(nhl, NULL, NULL); //TODO replace NULL with actual struct
			break;
	}
	
	//drain_all_the_buffer
	evbuffer_drain(in, len);
}


int configure_netlink(void)
{
	struct bufferevent *bev;
	struct nl_msg *msg;
	void *hdr;
	int group;
	int err;

	netlink_sk = nl_socket_alloc();

	genl_connect(netlink_sk);

	DLOG(MAM_NETLINK_NOISY_DEBUG2, "---------------\n");

	family = genl_ctrl_resolve(netlink_sk, "MAM_MPTCP");
	if (family == 0)
		perror("MAM_MPTCP netlink family not found\n");
		
	group = genl_ctrl_resolve_grp(netlink_sk, "MAM_MPTCP", "MAM_MPTCP");
    if (group <= 0)
        perror("MAM_MPTCP netlink group not found\n");
	else
		DLOG(MAM_NETLINK_NOISY_DEBUG2, "group id: %u\n", group);

	msg = nlmsg_alloc();
	
	if (msg == NULL)
		perror("Could not alloc netlink message\n");
	
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0, MAM_MPTCP_C_INIT, 1);
	
	if (hdr == NULL)
		perror("Header of netlink message not written.\n");
	
	if (nla_put_string(msg, MAM_MPTCP_A_STRMSG, "init") < 0)
		perror("Could not add attribute to init message\n");
	
	if((err = nl_send_auto(netlink_sk, msg)) < 0)
		perror("Could not send netlink message\n");
		
	DLOG(MAM_NETLINK_NOISY_DEBUG2, "%d bytes sent\n", err);

	nlmsg_free(msg);
	
	nl_socket_set_nonblocking(netlink_sk);
	//currently there is no check implemented
	nl_socket_disable_seq_check(netlink_sk);
	
	nl_socket_add_membership(netlink_sk, group);

	//TODO: investigate if close_on_free conflicts with our own free
	bev = bufferevent_socket_new(global_mctx->ev_base, nl_socket_get_fd(netlink_sk), BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, netlink_readcb, NULL, NULL, NULL); //(void *) foo);
	
	bufferevent_setwatermark(bev, EV_READ, 15, 0);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	
	DLOG(MAM_NETLINK_NOISY_DEBUG2, "---------------\n");
	return 0;
}

int create_new_flow(struct mptcp_flow_info *flow)
{
	struct nl_msg *msg_out;
	void *hdr;
	int err;

	//respond with newflow message via netlink to fullmesh-userspace pathmanager
	msg_out = nlmsg_alloc();
	
	if (msg_out == NULL)
		perror("Could not alloc netlink message\n");
	
	hdr = genlmsg_put(msg_out, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0, MAM_MPTCP_C_NEWFLOW, 1);
	
	if (hdr == NULL)
		perror("Header of netlink message not written.\n");
	
	if (nla_put_flag(msg_out, MAM_MPTCP_A_OK) < 0)
		perror("Could not add OK to new flow response message\n");
		
	if (nla_put_u64(msg_out, MAM_MPTCP_A_INODE, flow->inode) < 0)
		perror("Could not add INODE to new flow response message\n");
		
	if (nla_put_u32(msg_out, MAM_MPTCP_A_TOKEN, flow->token) < 0)
		perror("Could not add TOKEN to new flow response message\n");
		
	if (flow->loc_addr.ss_family == AF_INET)
	{
		if (nla_put_u32(msg_out, MAM_MPTCP_A_IPV4_LOC, (uint32_t)(((struct sockaddr_in*)&flow->loc_addr)->sin_addr).s_addr) < 0)
			perror("Could not add IPV4_LOC to new flow response message\n");
	}
	else
	if (flow->loc_addr.ss_family == AF_INET6)
	{	
		if (nla_put(msg_out, MAM_MPTCP_A_IPV6_LOC, sizeof(struct in6_addr), &((struct sockaddr_in6*)&flow->loc_addr)->sin6_addr) < 0)
			perror("Could not add IPV6_LOC to new flow response message\n");
		printf("is v6 - loc\n");
	}
	else
	{
		perror("loc_addr has no family\n");
		goto error_case;
	}

	if (flow->rem_addr.ss_family == AF_INET)
	{
		if (nla_put_u32(msg_out, MAM_MPTCP_A_IPV4_REM, (uint32_t)(((struct sockaddr_in*)&flow->rem_addr)->sin_addr).s_addr) < 0)
			perror("Could not add IPV4_REM to new flow response message\n");
	}
	else
	if (flow->rem_addr.ss_family == AF_INET6)
	{
		if (nla_put(msg_out, MAM_MPTCP_A_IPV6_REM, sizeof(struct in6_addr), &((struct sockaddr_in6*)&flow->rem_addr)->sin6_addr) < 0)
			perror("Could not add IPV6_REM to new flow response message\n");

		printf("is v6 - rem\n");
	}
	else
	{
		perror("rem_addr has no family\n");
		goto error_case;
	}

	if (flow->rem_addr.ss_family == AF_INET6)
	{
		if (nla_put_flag(msg_out, MAM_MPTCP_A_IS_V6) < 0)
			perror("Could not add IS_V6 to new flow response message\n");
	}

	if (nla_put_u8(msg_out, MAM_MPTCP_A_LOC_ID, flow->loc_id) < 0)
		perror("Could not add LOC_ID to new flow response message\n");
	if (nla_put_u8(msg_out, MAM_MPTCP_A_LOC_PRIO, flow->loc_low_prio) < 0)
		perror("Could not add LOC_PRIO to new flow response message\n");
	if (nla_put_u8(msg_out, MAM_MPTCP_A_REM_ID, flow->rem_id) < 0)
		perror("Could not add REM_ID to new flow response message\n");
	if (nla_put_u8(msg_out, MAM_MPTCP_A_REM_PRIO, flow->rem_low_prio) < 0)
		perror("Could not add REM_PRIO to new flow response message\n");
	if (nla_put_u8(msg_out, MAM_MPTCP_A_REM_BIT, flow->rem_bitfield) < 0)
		perror("Could not add REM_BIT to new flow response message\n");
	if (nla_put_u16(msg_out, MAM_MPTCP_A_REM_PORT, flow->rem_port) < 0)
		perror("Could not add REM_PORT to new flow response message\n");
	
	if((err = nl_send_auto(netlink_sk, msg_out)) < 0)
		perror("Could not send netlink message\n");
	else
		printf("sent message out\n");

error_case:
	nlmsg_free(msg_out);
	return 0;
}

void shutdown_netlink(void)
{
	nl_close(netlink_sk);
	nl_socket_free(netlink_sk);
}
