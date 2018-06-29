/** \file mam_iface.c
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/errno.h>

#ifdef IS_LINUX
#include <linux/wireless.h>
#include <linux/nl80211.h>
#endif

#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ifaddrs.h>

#ifdef HAVE_LIBNL
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/idiag/idiagnl.h>
#include <netlink/idiag/vegasinfo.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/attr.h>
#endif

#include <pcap.h>
#include <pthread.h>

#undef __USE_MISC //Dirty hack: Prevent breaking previous defines from linux/if.h (included by netlink)
#include <net/if.h>
#define __USE_MISC

#ifdef AF_LINK
#include <net/if_dl.h>
#endif
#ifdef AF_PACKET
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#endif
#include <net/route.h>
#include <netinet/if_ether.h>

#include "dlog.h"
#include "muacc_util.h"

#include "mam.h"
#include "mam_util.h"

#ifndef MAM_IF_NOISY_DEBUG0
#define MAM_IF_NOISY_DEBUG0 0
#endif

#ifndef MAM_IF_NOISY_DEBUG1
#define MAM_IF_NOISY_DEBUG1 1
#endif

#ifndef MAM_IF_NOISY_DEBUG2
#define MAM_IF_NOISY_DEBUG2 0
#endif

#ifndef MAM_IF_NOISY_DEBUG3
#define MAM_IF_NOISY_DEBUG3 0
#endif

#define BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

#ifdef HAVE_LIBNL
/** Data structure for netlink state of an interface that communicates through nl80211 to get load
*/
struct netlink_state
{
	struct nl_sock *sock;				/**< Netlink socket */
	int nl80211_id;						/**< nl80211 driver ID as destination for messages */
	struct nl_cb *cb;					/**< Pointer to callback functions to process netlink messages */
	unsigned int dev_id;				/**< Device ID of this interface, for netlink messages */
	char *dev_name;						/**< Device name of this interface */
	unsigned int monitor_iface_status;	/**< Creation status of the monitor interface */
};
#endif

/* Function declaration: Add a new interface to list */
struct iface_list *_add_iface_to_list (GSList **ifacel, char *if_name);
int is_iface_wireless (char *if_name);

#ifdef HAVE_LIBNL
int prepare_netlink_socket_for_iface(struct netlink_state *nlstate, char *dev_iface);
void close_netlink_socket(struct netlink_state *nlstate);

int make_monitor_iface(struct netlink_state *nlstate, char *device, char *phy_iface);
int setup_sniffer(pcap_t **sniffer, char *device, char *errbuf);
void close_monitor_interface(char *device);
int bring_iface_up (char* mon_device);
#endif

/** Compare a src_prefix_list struct with a src_prefix_model
 *  Return 0 if they are equal, 1 if not, -1 on error */
int compare_src_prefix (gconstpointer listelement, gconstpointer model)
{
	struct src_prefix_model *m = (struct src_prefix_model *) model;
	struct src_prefix_list *cur = (struct src_prefix_list *) listelement;
	if (cur == NULL || model == NULL)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "WARNING: called with NULL argument\n");
		return -1;
	}

	/* different interface or family */
	if( ((cur->pfx_flags)^m->flags) & m->flags )
		return 1;
	if(m->family != 0 && cur->family != m->family)
		return 1;
	if(m->if_name != NULL && strcmp(cur->if_name, m->if_name) != 0)
		return 1;
	if( m->addr == NULL ||
		(m->family == AF_INET6 &&
		_cmp_in6_addr_with_mask(
			&(((struct sockaddr_in6 *) m->addr)->sin6_addr),
			&(((struct sockaddr_in6 *) cur->if_addrs->addr)->sin6_addr),
			&(((struct sockaddr_in6 *) cur->if_netmask)->sin6_addr)) == 0
		) || (
		m->family == AF_INET &&
		_cmp_in_addr_with_mask(
			&(((struct sockaddr_in *) m->addr)->sin_addr),
			&(((struct sockaddr_in *) cur->if_addrs->addr)->sin_addr),
			&(((struct sockaddr_in *) cur->if_netmask)->sin_addr)) == 0
		)
	)
	{
		DLOG(MAM_IF_NOISY_DEBUG2, "prefix matches model!\n");
		return 0;
	}
	else
		return 1;
}

/** From an old source prefix list, generate a new one
 *  that only includes prefixes matching certain criteria */
void filter_prefix_list (GSList *old, GSList **new, unsigned int pfx_flags, const char *if_name, int family, const struct sockaddr *addr)
{
    DLOG(MAM_IF_NOISY_DEBUG2, "filter prefix list\n");
	/* Set criteria for matching addresses */
	struct src_prefix_model m = { pfx_flags, if_name, family, addr };

	/* Go through the prefix list */
	while (old != NULL)
	{
		/* Find next element that matches our criteria */
		old = g_slist_find_custom(old->next, (gconstpointer) &m, &compare_src_prefix);
		if (old == NULL) break;

		/* Append matching element to new list */
		*new = g_slist_append(*new, old->data);
	}
}

/** Append an address to a sockaddr_list */
static int _append_sockaddr_list (
	struct sockaddr_list **dst,
    struct sockaddr *addr, 
	socklen_t addr_len )
{
	*dst = malloc(sizeof(struct sockaddr_list));
	if(*dst == NULL) { DLOG(1, "malloc failed"); return(-1); } 
	memset(*dst, 0, sizeof(struct sockaddr_list));
	(*dst)->addr = _muacc_clone_sockaddr(addr, addr_len);
	(*dst)->addr_len = addr_len;
	return(0);
}

/** Helper function that matches interface names.
 *  Returns 0 if the given ifname matches the given listelement's interface name
 */
int compare_if_name (gconstpointer listelement, gconstpointer ifname)
{
	struct iface_list *cur = (struct iface_list *) listelement;
	char *match_name = (char *) ifname;

	if (cur == NULL || match_name == NULL)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "WARNING: called with NULL argument\n");
		return -1;
	}

	if (cur->if_name != NULL && strcmp(cur->if_name, match_name) == 0)
	{
		// Interface names match
		return 0;
	}
	else
	{
		return 1;
	}

}

/** Query the wireless extension protocol for this interface, which only exists if
 *  the interface is wireless in a 802.11 sense
 *  Returns 1 if the interface is wireless, 0 if not, and -1 on error
 */
#ifdef IS_LINUX
int is_iface_wireless (char *if_name)
{
	if (if_name == NULL)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "Called with NULL interface\n");
		return -1;
	}

	// Prepare socket and query data structure
	int sock = -1;
	struct iwreq data;
	memset(&data, 0 , sizeof(data));
	// Write interface name to query data structure
	strncpy(data.ifr_name, if_name, IFNAMSIZ);

	// Open socket for querying the wireless extension protocol
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "Cannot open socket - no way to determine if interface is wireless\n");
		return -1;
	}

	// Do ioctl request for the wireless extension protocol of this interface
	int ret = -1;
	if ((ret = ioctl(sock, SIOCGIWNAME, &data)) == 0)
	{
		DLOG(MAM_IF_NOISY_DEBUG2, "Interface %s is wireless (802.11)!\n", if_name);
		close(sock);
		return 1;
	}
	else
	{
		DLOG(MAM_IF_NOISY_DEBUG2, "Interface %s is not wireless (802.11)! (returned %d)\n", if_name, ret);
		close(sock);
		return 0;
	}
}
#endif


/*Code to turn on the packet capture which gets the BSS load element passively*/
int setup_sniffer(pcap_t **sniffer, char *device, char *errbuf) {
    // Open capturing device
    *sniffer = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (*sniffer == NULL) {
		DLOG(MAM_IF_NOISY_DEBUG3, "Device %s COULDN'T BE OPENED! \n Error: %s\n", device, errbuf);
		return -1;
	} else {
		DLOG(MAM_IF_NOISY_DEBUG3, "Device %s opened!\n", device);
	}

	//Set the capturing device into non-blocking mode
	int nonblock = pcap_setnonblock(*sniffer, 1, errbuf);
	if (nonblock == -1) {
		DLOG(MAM_IF_NOISY_DEBUG3, "Couldn't set non-blocking mode on capturing device %s!\n Error: %s\n", device, errbuf);
		return -1;
	} else if (nonblock == 0) {
		DLOG(MAM_IF_NOISY_DEBUG3, "Set nonblocking mode on capturing device %s!\n", device);
	} else {
		DLOG(MAM_IF_NOISY_DEBUG3, "Couldn't set non-blocking mode on capturing device %s!\n Unknown error...\n", device);
		return -1;
	}

	// Prepare the Berkeley Packet Filter for the capturing device. Capture only IEEE 802.11 Standard Beacon Frames
	struct bpf_program filter;
	char filter_primitive[] = "type mgt subtype beacon";

	bpf_u_int32 netmask;
	bpf_u_int32 ip_addr;
	pcap_lookupnet(device, &ip_addr, &netmask, errbuf);

	// Compile the Berkeley Packet Filter with the filter primitive for the capturing device
	if (pcap_compile(*sniffer, &filter, filter_primitive, 0, netmask) == -1) {
		DLOG(MAM_IF_NOISY_DEBUG3, "Could not compile filter %s for capturing device %s. Error: %s\n", filter_primitive, device, pcap_geterr(*sniffer));
		return -1;
	} else {
		DLOG(MAM_IF_NOISY_DEBUG3, "Filter successfully compiled for capturing device %s.\n", device);
	}

	// Set the Berkeley Packet Filter on the capturing device
	if (pcap_setfilter(*sniffer, &filter) == -1) {
		fprintf(stderr, "Could not set the filter %s on capturing device %s. Error: %s\n", filter_primitive, device, pcap_geterr(*sniffer));
		return -1;
	} else {
		DLOG(MAM_IF_NOISY_DEBUG3, "Filter successfully set on capturing device %s.\n", device);
		return 0;
	}
}

#ifdef HAVE_LIBNL
/*Handler for netlink acknowledgements*/
static int ack_handler(struct nl_msg *msg, void *arg) {
	DLOG(MAM_IF_NOISY_DEBUG3, "We got an ACK from netlink!\n");
	return NL_SKIP;
}

/*Handler for netlink finish messages*/
static int finish_handler(struct nl_msg *msg, void *arg) {
	DLOG(MAM_IF_NOISY_DEBUG3, "We finished receiving netlink messages!\n");
	return NL_SKIP;
}

/*Handler for netlink error messages*/
static int handle_netlink_errors(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
	// Display error message, then skip to the next message
	DLOG(MAM_IF_NOISY_DEBUG3, "Got netlink error: %d (%s)\n", nlerr->error, nl_geterror(-1 * nlerr->error));
	if (nlerr->error == -23) {
		return NL_SKIP;
	}
	return NL_SKIP;
}

/*Handler for valid netlink messages. In our case to check if the monitor interface was created successfully*/
static int handle_valid_netlink(struct nl_msg *msg, void *arg) {
	struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	struct netlink_state *nlstate = arg;
	struct nlattr *attr_msg[NL80211_ATTR_MAX + 1];
	nla_parse(attr_msg, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), NULL);
	DLOG(MAM_IF_NOISY_DEBUG3, "We got a netlink message!\n");

	if (hdr->cmd == NL80211_CMD_NEW_INTERFACE) {
		DLOG(MAM_IF_NOISY_DEBUG3, "Successfully created the monitor interface!\n");
		nlstate->monitor_iface_status = 1;
		return NL_STOP;
	} else {
		DLOG(MAM_IF_NOISY_DEBUG3, "This netlink message didn't contain anything important!\n");
	}

	return NL_SKIP;
}

/*This function prepares a netlink socket to execute commands on specified interface (dev_iface)*/
int prepare_netlink_socket_for_iface(struct netlink_state *nlstate, char *dev_iface) {
	// Prepare and allocate a socket for the desired interface
	nlstate->sock = nl_socket_alloc();
	nlstate->dev_id = if_nametoindex(dev_iface);
	nlstate->dev_name = dev_iface;
	if (!nlstate->sock) {
		DLOG(MAM_IF_NOISY_DEBUG1, "Failed to allocate netlink socket for monitor interface creation\n");
		return -1;
	}

	// Connect the socket
	if (genl_connect(nlstate->sock) < 0) {
		DLOG(MAM_IF_NOISY_DEBUG1, "Failed to connect netlink socket for monitor interface creation\n");
		nl_socket_free(nlstate->sock);
		free(nlstate);
		return -1;
	}

	// Get the id of netlink socket associated with desired interface
	nlstate->nl80211_id = genl_ctrl_resolve(nlstate->sock, "nl80211");
	if (nlstate->nl80211_id < 0) {
		DLOG(MAM_IF_NOISY_DEBUG1, "nl80211 interface not found for monitor interface creation\n");
		nl_socket_free(nlstate->sock);
		free(nlstate);
		return -1;
	}

	// Allocate netlink callbacks
	nlstate->cb = nl_cb_alloc(NL_CB_VERBOSE);
	if (!nlstate->cb) {
		DLOG(MAM_IF_NOISY_DEBUG1, "Failed to allocate netlink callback for monitor interface creation\n");
		nl_socket_free(nlstate->sock);
		free(nlstate);
		return -1;
	}

	// Prepare a flag that indicates successfull monitor interface creation. Firstly set it to 0.
	nlstate->monitor_iface_status = 0;

	// Set the callback for all valid messages to a function that parses them
	nl_cb_set(nlstate->cb, NL_CB_VALID, NL_CB_CUSTOM, handle_valid_netlink, nlstate);

	// Set the error message handler to a function that prints the error
	nl_cb_err(nlstate->cb, NL_CB_CUSTOM, handle_netlink_errors, NULL);

	// Set a callback for the message when we are finished
	nl_cb_set(nlstate->cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);

	// Set the callback for ACKs
	nl_cb_set(nlstate->cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, NULL);

	return 0;
}

/*Close the netlink socket and free data structures associated with it*/
void close_netlink_socket(struct netlink_state *nlstate) {
	if (nlstate != NULL) {
		nl_cb_put(nlstate->cb);
		nl_socket_free(nlstate->sock);
		free(nlstate);
	}
	DLOG(MAM_IF_NOISY_DEBUG3, "Closed netlink socket\n");
}

/*Prepare the monitor interface for beacon frames capture*/
int make_monitor_iface (struct netlink_state *nlstate, char *mon_device, char *dev_iface) {
	// Prepare the netlink message to create the monitor interface
	int ret;
	struct nl_msg *msg = nlmsg_alloc();
	if (!msg) {
		DLOG(MAM_IF_NOISY_DEBUG1, "Failed to allocate netlink message for monitor interface %s creation\n", mon_device);
		return -1;
	}
	genlmsg_put(msg, 0, 0, nlstate->nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, nlstate->dev_id);
	nla_put_string(msg, NL80211_ATTR_IFNAME, mon_device);
	nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	// Send the message
	ret = nl_send_auto(nlstate->sock, msg);

	DLOG(MAM_IF_NOISY_DEBUG3, "Requested monitor interface (%s) creation with result: %d\n", mon_device, ret);

	// Receive netlink messages and determine whether the interface creation was successful or not
	ret = nl_recvmsgs_report(nlstate->sock, nlstate->cb);

	DLOG(MAM_IF_NOISY_DEBUG3, "Analyzed %d netlink messages\n", ret);

    nlmsg_free(msg);
	if (nlstate->monitor_iface_status != 1) return -1;
	else return 0;
}

/*Bring the monitor interface up using IOCTL*/
int bring_iface_up (char* mon_device) {
	struct ifreq if_data;
	memset(&if_data, 0 , sizeof(if_data));
	strncpy(if_data.ifr_name, mon_device, IFNAMSIZ);

    // Open socket for interface querying
    int sock = -1;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		DLOG(MAM_IF_NOISY_DEBUG3, "Cannot open socket - we can't bring the interface up\n");
		return -1;
	}

	// Do ioctl request for the wireless extension protocol of this interface
	int ret = -1;
	if_data.ifr_flags |= IFF_UP; // Set the flag to bring interface up
	if ((ret = ioctl(sock, SIOCSIFFLAGS, &if_data)) != 0) {
		DLOG(MAM_IF_NOISY_DEBUG3, "IOCTL on interface %s FAILED! We couldn't bring the interface up\n", mon_device);
		close(sock);
		return -1;
	} else {
		DLOG(MAM_IF_NOISY_DEBUG3, "Interface %s brought up.\n", mon_device);
	}
	close(sock);
	return 0;
}

/*Destroy the monitor interface*/
void close_monitor_interface(char *mon_device) {
	// Prepare the netlink socket for monitor interface deconstruction
	struct netlink_state *nlstate = malloc(sizeof(struct netlink_state));
	prepare_netlink_socket_for_iface(nlstate, mon_device);
	int ret;
	// Prepare the netlink message to do just that
	struct nl_msg *msg = nlmsg_alloc();
	if (!msg) {
		DLOG(MAM_IF_NOISY_DEBUG3, "Failed to allocate netlink message for monitor interface creation\n");
		close_netlink_socket(nlstate);
		return;
	}
	genlmsg_put(msg, 0, 0, nlstate->nl80211_id, 0, 0, NL80211_CMD_DEL_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, nlstate->dev_id);

	// Send the message and receive the result
	ret = nl_send_auto(nlstate->sock, msg);

	DLOG(MAM_IF_NOISY_DEBUG3, "Requested to delete interface %s with result: %d\n", mon_device, ret);

	ret = nl_recvmsgs_report(nlstate->sock, nlstate->cb);

	DLOG(MAM_IF_NOISY_DEBUG3, "Analyzed %d netlink messages\n", ret);
    nlmsg_free(msg);

	close_netlink_socket(nlstate);
}
#endif /* HAVE_LIBNL */

/** Add an interface to the interface list, if it does not exist there yet
 *  In any case, return a pointer to the interface list item
 */
struct iface_list *_add_iface_to_list (
	GSList **ifacel,
	char *if_name)
{
	if (if_name == NULL)
	{
		DLOG(MAM_IF_NOISY_DEBUG1, "Cannot add interface \"NULL\"!\n");
		return NULL;
	} else {
		DLOG(MAM_IF_NOISY_DEBUG2, "Adding interface \"%s\"!\n", if_name);
	}
	GSList *ifacelistitem = NULL;

	/* Lookup this interface name in the interface list */
	ifacelistitem = g_slist_find_custom(*ifacel, (gconstpointer) if_name, &compare_if_name);

	if (ifacelistitem != NULL)
	{
		/* Interface name already found in list: Return this interface list item */
		DLOG(MAM_IF_NOISY_DEBUG2, "Interface %s already in list. Nothing to add to list.\n", if_name);
		return ifacelistitem->data;
	}
	else
	{
		DLOG(MAM_IF_NOISY_DEBUG2, "Adding interface %s to list\n", if_name);

		/* Interface name not found in list: Add it */
		struct iface_list *new = NULL;
		new = malloc(sizeof(struct iface_list));
		if (new == NULL)
		{
			DLOG(MAM_IF_NOISY_DEBUG1, "malloc for interface list element failed!\n");
			return NULL;
		}
		else
		{
			/* Create new interface list item */
			memset(new, 0, sizeof(struct iface_list));
			new->if_name = _muacc_clone_string(if_name);
			new->measure_dict = g_hash_table_new(g_str_hash, g_str_equal);

			new->additional_info = MAM_IFACE_UNKNOWN_LOAD;
            /* Checking for the wireless extension is currently only working on linux */
            #ifdef IS_LINUX
			if (is_iface_wireless(if_name) == 1)
			{
				// Query 802.11 station info for this interface
				new->additional_info |= MAM_IFACE_WIFI_STATION_INFO;
                #ifdef HAVE_LIBNL
				// We know that it is a wireless interface so we would like to query the bss load on it.
				new->additional_info |= MAM_IFACE_QUERY_BSS_LOAD;
				DLOG(MAM_IF_NOISY_DEBUG3, "Creating a virtual monitor interface and beacon frames capture for wireless interface %s!\n", new->if_name);
				struct netlink_state *nlstate = malloc(sizeof(struct netlink_state));
				if (nlstate == NULL) {
					DLOG(MAM_IF_NOISY_DEBUG3, "Failed to allocate netlink state for %s!\n", new->if_name);
					new->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
					new->additional_info &= ~(MAM_IFACE_WIFI_STATION_INFO);
					*ifacel = g_slist_append(*ifacel, (gpointer) new);
					return new;
				} else {
					DLOG(MAM_IF_NOISY_DEBUG3, "Successfully allocated netlink state for %s!\n", new->if_name);
				}
				// Prepare a netlink socket for the interface we are currently working on
				int result = prepare_netlink_socket_for_iface(nlstate, new->if_name);
				if (result != 0) {
					DLOG(MAM_IF_NOISY_DEBUG3, "Failed to prepare netlink socket for %s!\n", new->if_name);
					free(nlstate);
					new->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
					new->additional_info &= ~(MAM_IFACE_WIFI_STATION_INFO);
					*ifacel = g_slist_append(*ifacel, (gpointer) new);
					return new;
				} else {
					DLOG(MAM_IF_NOISY_DEBUG3, "Prepared the netlink socket for %s\n", new->if_name);
				}

				//Set up everything needed for passive capture of beacon frames
				char mon_device[strlen(new->if_name) + 3];
				char mon_name[4] = "mon\0";
				strcpy(mon_device, new->if_name);
				strcat(mon_device, mon_name);
				int monitor_already_exists = 0;
				if (if_nametoindex(mon_device) == 0){ // First, check if there exists such monitor interface
					if (make_monitor_iface(nlstate, mon_device, new->if_name) == 0) { // Create the monitor interface
						DLOG(MAM_IF_NOISY_DEBUG3, "Virtual monitor interface %s created!\n", mon_device);
						int temp = bring_iface_up(mon_device);
						if (temp != 0) { // Bring the monitor interface up
							DLOG(MAM_IF_NOISY_DEBUG3, "Couldn't bring virtual monitor interface %s up!\n", mon_device);
							close_monitor_interface(mon_device);
							close_netlink_socket(nlstate);
							new->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
							*ifacel = g_slist_append(*ifacel, (gpointer) new);
							return new;
						} else {
							DLOG(MAM_IF_NOISY_DEBUG3, "Virtual monitor interface %s brought up!\n", mon_device);
						}
					} else {
						DLOG(MAM_IF_NOISY_DEBUG3, "Couldn't create virtual monitor interface %s!\n", mon_device);
						close_monitor_interface(mon_device);
						close_netlink_socket(nlstate);
						new->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
						*ifacel = g_slist_append(*ifacel, (gpointer) new);
						return new;
					}
				} else {
					DLOG(MAM_IF_NOISY_DEBUG3, "Virtual monitor interface %s already exists!\n", mon_device);
					monitor_already_exists = 1;
					int temp = bring_iface_up(mon_device);
					if (temp != 0) {
						DLOG(MAM_IF_NOISY_DEBUG3, "Couldn't bring virtual monitor interface %s up!\n", mon_device);
						close_monitor_interface(mon_device);
						close_netlink_socket(nlstate);
						new->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
						*ifacel = g_slist_append(*ifacel, (gpointer) new);
						return new;
					} else {
						DLOG(MAM_IF_NOISY_DEBUG3, "Virtual monitor interface %s brought up!\n", mon_device);
					}
				}

				// Create the packet capture
				char errbuf[PCAP_ERRBUF_SIZE];
				pcap_t *snf = NULL;
				setup_sniffer(&snf, mon_device, errbuf);
				if (snf == NULL) {
					DLOG(MAM_IF_NOISY_DEBUG3, "Packet capture failed to set up on capturing device %s!\n", mon_device);
					close_monitor_interface(mon_device);
					close_netlink_socket(nlstate);
					new->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
					*ifacel = g_slist_append(*ifacel, (gpointer) new);
					return new;
				} else {
					DLOG(MAM_IF_NOISY_DEBUG3, "Packet capture is properly set up on device %s!\n", mon_device);
				}
				close_netlink_socket(nlstate);
                struct wifi_state *wifi = malloc(sizeof(struct wifi_state));
                memset(wifi, 0, sizeof(struct wifi_state));
				if (wifi == NULL) {
					DLOG(MAM_IF_NOISY_DEBUG3, "Failed to allocate wifi state for %s!\n", new->if_name);
					new->additional_info &= ~(MAM_IFACE_QUERY_BSS_LOAD);
					*ifacel = g_slist_append(*ifacel, (gpointer) new);
					return new;
                }
                wifi->sniffer = snf;
                wifi->monitor_already_existed = monitor_already_exists;
                new->query_state = wifi;
                #endif
			}
            #endif

			/* Append to list */
			*ifacel = g_slist_append(*ifacel, (gpointer) new);
			return new;
		}
	}
}

/** Incorporate an address into the source prefix list:
 *  If a matching prefix exists, add it to this prefix' addr_list
 *  If no matching prefix exists yet, create one
 */
static void _scan_update_prefix (
	GSList **spfxl,
	struct iface_list *iflistentry,
	char *if_name, unsigned int if_flags,
	int family,
	struct sockaddr *addr,
	struct sockaddr *mask)
{
	GSList *cur = NULL;
	size_t family_size = (family == AF_INET)  ? sizeof(struct sockaddr_in)  :
	 					 (family == AF_INET6) ? sizeof(struct sockaddr_in6) :
						 -1;
	struct sockaddr_list *cus;
	
	
	/* scan through prefixes */
	struct src_prefix_model model = {PFX_ANY, if_name, family, addr, family_size};
	cur = g_slist_find_custom(*spfxl, (gconstpointer) &model, &compare_src_prefix);

	if (cur != NULL)
	{
		/* Prefix already exists within the list: append this address to its address list */

		for(cus = ((struct src_prefix_list *)cur->data)->if_addrs; cus->next != NULL; cus = cus->next);
		; 
		_append_sockaddr_list( &(cus->next), addr, family_size);
		return;			
	}
	
	/* we have a new prefix: append it to the prefix list */
	
	/* allocate memory */
	struct src_prefix_list *new = NULL;
	new = malloc(sizeof(struct src_prefix_list));
	if(new == NULL)
		{ DLOG(1, "malloc failed"); return; } 
	memset(new, 0, sizeof(struct src_prefix_list));
	
	/* copy data */
	new->if_name = _muacc_clone_string(if_name);
	new->family = family;
	new->if_flags = if_flags;
	_append_sockaddr_list( &(new->if_addrs), addr, family_size);
	new->if_netmask = _muacc_clone_sockaddr(mask, family_size);
	new->if_netmask_len = family_size;

	/* add pointer to the interface list item of the interface that this prefix belongs to */
	new->iface = iflistentry;

	new->measure_dict = g_hash_table_new(g_str_hash, g_str_equal);
	
	/* append to list */
	*spfxl = g_slist_append(*spfxl, (gpointer) new);

	return;
}

/** Scan for interfaces/addresses available on the host
 *  Create a new src_prefix_list and add all active interfaces, prefixes and addresses to it
 */
int update_src_prefix_list (mam_context_t *ctx )
{
	GSList **spfxl = &ctx->prefixes;
	GSList **ifacel = &ctx->ifaces;

    struct ifaddrs *ifaddr, *ifa;
    int family;

    DLOG(MAM_IF_NOISY_DEBUG0, "creating a list of the currently active interfaces\n");

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return(-1);
    }
	
	if(*spfxl != NULL) 
	{
		g_slist_free_full(*spfxl, &_free_src_prefix_list);
	}

	if(*ifacel != NULL)
	{
		g_slist_free_full(*ifacel, &_free_iface_list);
	}

    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
		if((ifa->ifa_flags & IFF_UP)==0) 
		{
            DLOG(MAM_IF_NOISY_DEBUG2, "%s: interface down - skipping\n", ifa->ifa_name);
        	continue;
		} 
		else if(ifa->ifa_addr == NULL) 
		{
            DLOG(MAM_IF_NOISY_DEBUG2, "%s: address family: (NULL) - skipping\n", ifa->ifa_name);
            continue;
		}
		
		family = ifa->ifa_addr->sa_family;
		
		if (family == AF_INET || family == AF_INET6)
        {
            DLOG(MAM_IF_NOISY_DEBUG2, "%s: adding address (", ifa->ifa_name);
			#if MAM_IF_NOISY_DEBUG2 != 0
        	/* Display interface name and family (including symbolic
               form of the latter for the common families) */
		    char addr[NI_MAXHOST];
		    char mask[NI_MAXHOST];
			int s;
            s = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	        s = getnameinfo(ifa->ifa_netmask,
	            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
	            mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s == 0)
			{
				fprintf(stderr, "family: %d%s, address: %s mask: %s)\n",
					 family,
					 (family == AF_INET) ?   " (AF_INET)" :
					 (family == AF_INET6) ?  " (AF_INET6)" : "",
					 addr, mask);
			}
			#endif

			/* add to interface list if it does not exist yet */
			struct iface_list *iflistentry = _add_iface_to_list( ifacel, ifa->ifa_name);
				 
			/* add to source prefix list */
			_scan_update_prefix( spfxl, iflistentry,
				ifa->ifa_name, ifa->ifa_flags,
				family, ifa->ifa_addr, ifa->ifa_netmask );
		}
    }

    freeifaddrs(ifaddr);
    return(0);
}

/** Tear down a interface list structure */
void _free_iface_list (gpointer data)
{
	struct iface_list *element = (struct iface_list *) data;

    #ifdef HAVE_LIBNL
	struct wifi_state *wifi = element->query_state;
	if ((wifi != NULL) && (element->if_name != NULL))
	{
		char mon_device[strlen(element->if_name) + 3];
		char mon_name[4] = "mon\0";
		strcpy(mon_device, element->if_name);
		strcat(mon_device, mon_name);
		// Close the packet capture
		if (wifi->sniffer != NULL) {
			pcap_close(wifi->sniffer);
			DLOG(MAM_IF_NOISY_DEBUG3, "Closed the capturing device on interface %s!\n", mon_device);
		}
		// Delete the virtual monitor interface
		if (if_nametoindex(mon_device) != 0 && !(wifi->monitor_already_existed)) {
			close_monitor_interface(mon_device);
			DLOG(MAM_IF_NOISY_DEBUG3, "Deleted virtual monitor interface %s!\n", mon_device);
		}
        free(wifi);
	}
    #endif
	if (element->if_name != NULL) {
		free(element->if_name);
	}

	if(element->policy_set_dict != NULL)
		g_hash_table_destroy(element->policy_set_dict);

	if(element->measure_dict != NULL)
		g_hash_table_destroy(element->measure_dict);

	free(element);

	return;
}

/** Tear down a source prefix list structure */
void _free_src_prefix_list (gpointer data)
{
	struct src_prefix_list *element = (struct src_prefix_list *) data;
	struct sockaddr_list *addrlist = NULL;
	struct sockaddr_list *curra = NULL;
	
	if (element->if_name != NULL)
		free(element->if_name);

	addrlist = element->if_addrs;
	while (addrlist != NULL)
	{
		curra = addrlist;
		addrlist = curra->next;
		
		if (curra->addr != NULL)
			free(curra->addr);
		
		free(curra);
	}
	
	if (element->if_netmask != NULL)
		free(element->if_netmask);

	if(element->evdns_base != NULL)
		evdns_base_free(element->evdns_base, 0);

	if(element->policy_set_dict != NULL)
		g_hash_table_destroy(element->policy_set_dict);

	if(element->measure_dict != NULL)
		g_hash_table_destroy(element->measure_dict);

	free(element);

	return;
}

