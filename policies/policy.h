/** \file policy.h
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <arpa/inet.h>

#include "clib/muacc.h"
#include "clib/muacc_util.h"
#include "lib/intents.h"
#include "mam/mam.h"

#include "mam/mptcp_netlink_parser.h"

void set_policy_info(gpointer elem, gpointer data);
void freepolicyinfo(gpointer elem, gpointer data);

int init(mam_context_t *mctx);
int cleanup(mam_context_t *mctx);
#ifdef HAVE_LIBNL
int on_new_subflow_request(mam_context_t *mctx, struct mptcp_flow_info *flow);
#endif
int on_resolve_request(request_context_t *rctx, struct event_base *base);
int on_connect_request(request_context_t *rctx, struct event_base *base);
int on_socketconnect_request(request_context_t *rctx, struct event_base *base);
int on_socketchoose_request(request_context_t *rctx, struct event_base *base);
