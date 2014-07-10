#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <arpa/inet.h>

#include "lib/muacc.h"
#include "lib/muacc_util.h"
#include "lib/intents.h"
#include "mam/mam.h"

void set_policy_info(gpointer elem, gpointer data);
void freepolicyinfo(gpointer elem, gpointer data);

int init(mam_context_t *mctx);
int cleanup(mam_context_t *mctx);
int on_resolve_request(request_context_t *rctx, struct event_base *base);
int on_connect_request(request_context_t *rctx, struct event_base *base);
int on_socketconnect_request(request_context_t *rctx, struct event_base *base);
