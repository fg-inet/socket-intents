/** \file   mam/mam_pmeasure.h
 *  \brief  Passive measurements for MAM to aid policies
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "mam.h"

void pmeasure_setup();
void pmeasure_callback(evutil_socket_t fd, short what, void *arg);
void pmeasure_cleanup();

void pmeasure_print_summary(void *pfx, void *data);
