/** \file mam_netlink.h
 *	Netlink functions
 */
#ifndef __MAM_NETLINK_H__
#define __MAM_NETLINK_H__

#include "mptcp_netlink_parser.h"
#include <event2/bufferevent.h>

void netlink_readcb(struct bufferevent*, void*);
int configure_netlink(void);
void shutdown_netlink(void);
int create_new_v4_flow(struct mptcp_flow_info *flow);

#endif /* __MAM_NETLINK_H__ */
