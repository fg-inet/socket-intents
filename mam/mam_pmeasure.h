/** \file   mam/mam_pmeasure.h
 *  \brief  Passive measurements for MAM to aid policies
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "mam.h"

void pmeasure_setup(mam_context_t *ctx);
void pmeasure_callback(evutil_socket_t fd, short what, void *arg);
void pmeasure_cleanup(mam_context_t *ctx);

void pmeasure_print_prefix_summary(void *pfx, void *data);
void pmeasure_print_iface_summary(void *ifc, void *data);

void pmeasure_log_prefix_summary(void *pfx, void *data);
void pmeasure_log_iface_summary(void *ifc, void *data);
