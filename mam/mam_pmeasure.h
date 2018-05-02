/** \file   mam/mam_pmeasure.h
 *  \brief  Passive measurements for MAM to aid policies
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include "mam.h"

#define SSID_PARAMETER_TAG 0
#define SUPPORTED_RATES_TAG 1
#define FH_PARAMETER_SET_TAG 2
#define DS_PARAMETER_SET_TAG 3
#define CF_PARAMETER_SET_TAG 4
#define TIM_TAG 5
#define IBSS_PARAMETER_SET_TAG 6
#define COUNTRY_INFO_TAG 7
#define FH_PARAMETERS_TAG 8
#define FH_PATTERN_TABLE_TAG 9
#define QBSS_LOAD_ELEMENT_TAG 11
#define EDCA_PARAMETER_SET_TAG 12
#define POWER_CONSTRAINT_TAG 32
#define TPC_REPORT_TAG 35
#define CHANNEL_SWITCH_ANNOUNCEMENT_TAG 37
#define QUIET_TAG 40
#define IBSS_DFS_TAG 41
#define ERP_INFORMATION_TAG 42
#define QOS_CAPABILITY_TAG 46
#define RSN_INFORMATION_TAG 48
#define ESR_TAG 50
#define VENDOR_SPECIFIC_TAG 221

void pmeasure_setup(mam_context_t *ctx);
void pmeasure_callback(evutil_socket_t fd, short what, void *arg);
void pmeasure_cleanup(mam_context_t *ctx);

void pmeasure_print_prefix_summary(void *pfx, void *data);
void pmeasure_print_iface_summary(void *ifc, void *data);

void pmeasure_log_prefix_summary(void *pfx, void *data);
void pmeasure_log_iface_summary(void *ifc, void *data);
