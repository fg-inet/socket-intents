/** \file dlog.h
 *  Logging utility
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <unistd.h>
#ifndef _DLOG_H_
#define _DLOG_H_ 1
#define DLOG_MAXLEN 512
extern int muacc_debug_fd;
#define dprint(file, line, function, ...)  { char t[DLOG_MAXLEN]; snprintf(t, sizeof(t), __VA_ARGS__); dprintf(muacc_debug_fd, "%6d %-32s l%4d: %s", (int) getpid(), function, line, t); }
#define DLOG(switch, ...) if (switch) dprint(__FILE__, __LINE__,__FUNCTION__,__VA_ARGS__) ;
#endif
