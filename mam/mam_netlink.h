/** \file mam_netlink.h
 *	Netlink functions
 */
#ifndef __MAM_NETLINK_H__
#define __MAM_NETLINK_H__

#ifndef __KERNEL__
#include <netlink/netlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#else
#include <linux/netlink.h>
#include <linux/genetlink.h>
#endif

void netlink_readcb(struct bufferevent*, void*);
int configure_netlink(void);
void shutdown_netlink(void);

#endif /* __MAM_NETLINK_H__ */
