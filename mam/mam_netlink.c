/**
 * \file mam_netlink.c
 *
 */

#include "mam.h"
#include "mam_netlink.h"
#include "mptcp_mam_netlink.h"


#ifndef MAM_NETLINK_NOISY_DEBUG0
#define MAM_NETLINK_NOISY_DEBUG0 1
#endif

#ifndef MAM_NETLINK_NOISY_DEBUG1
#define MAM_NETLINK_NOISY_DEBUG1 1
#endif

#ifndef MAM_NETLINK_NOISY_DEBUG2
#define MAM_NETLINK_NOISY_DEBUG2 1
#endif

extern struct mam_context *global_mctx;

struct nl_sock *netlink_sk;

void netlink_readcb(struct bufferevent *bev, void *dummy)
{
	struct evbuffer *in;
	struct nlmsghdr *nlh;
	struct nlattr *attrs[MAM_MPTCP_A_MAX+1];
	unsigned char *buf = NULL;
	size_t len;

	in = bufferevent_get_input(bev);
	len = evbuffer_get_length(in);
	buf = evbuffer_pullup(in, len);
	
	DLOG(MAM_NETLINK_NOISY_DEBUG2, "new netlink message!\n");
	
	nlh = (struct nlmsghdr *)buf;

	//TODO check all types ... 
	if (genlmsg_hdr(nlh)->cmd == MAM_MPTCP_C_NEWFLOW)
		DLOG(MAM_NETLINK_NOISY_DEBUG2, "new flow message\n");
	
	if(genlmsg_parse(nlh, 0, attrs, MAM_MPTCP_A_MAX, mam_mptcp_genl_policy) < 0)
		perror("could not parse netlink message attributes\n");
	
	if (attrs[MAM_MPTCP_A_IPV4])
		DLOG(MAM_NETLINK_NOISY_DEBUG2, "content of new flow: %u\n", nla_get_u32(attrs[MAM_MPTCP_A_IPV4]));
	
	//drain_all_the_buffer
	evbuffer_drain(in, len);
}


int configure_netlink(void)
{
	struct bufferevent *bev;
	struct nl_msg *msg;
	void *hdr;
	int family;
	int err;

	netlink_sk = nl_socket_alloc();

	genl_connect(netlink_sk);

	DLOG(MAM_NETLINK_NOISY_DEBUG2, "---------------\n");

	family = genl_ctrl_resolve(netlink_sk, "MAM_MPTCP");
	if (family == 0)
		perror("MAM_MPTCP netlink family not found\n");

	msg = nlmsg_alloc();
	
	if (msg == NULL)
		perror("Could not alloc netlink message\n");
	
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0, MAM_MPTCP_C_INIT, 1);
	
	if (hdr == NULL)
		perror("Header of netlink message not written.\n");
	
	if (nla_put_string(msg, MAM_MPTCP_A_MSG, "init") < 0)
		perror("Could not add attribute to init message\n");
	
	if((err = nl_send_auto(netlink_sk, msg)) < 0)
		perror("Could not send netlink message\n");
		
	DLOG(MAM_NETLINK_NOISY_DEBUG2, "%d bytes sent\n", err);

	nlmsg_free(msg);
	
	nl_socket_set_nonblocking(netlink_sk);
	//currently there is no check implemented
	nl_socket_disable_seq_check(netlink_sk);

	//TODO: investigate if close_on_free confricts with our own free
	bev = bufferevent_socket_new(global_mctx->ev_base, nl_socket_get_fd(netlink_sk), BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, netlink_readcb, NULL, NULL, NULL); //(void *) foo);
	
	bufferevent_setwatermark(bev, EV_READ, 15, 0);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	
	DLOG(MAM_NETLINK_NOISY_DEBUG2, "---------------\n");
	return 0;
}

void shutdown_netlink(void)
{
	nl_close(netlink_sk);
	nl_socket_free(netlink_sk);
}
