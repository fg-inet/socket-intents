/** \file mam_netlink.h
 *	Netlink functions
 */
#ifndef __MAM_NETLINK_H__
#define __MAM_NETLINK_H__

void netlink_readcb(struct bufferevent*, void*);
int configure_netlink(void);
void shutdown_netlink(void);

#endif /* __MAM_NETLINK_H__ */
