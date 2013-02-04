#include <unistd.h>
#ifndef DLOG_MAXLEN
#define DLOG_MAXLEN 512
#endif
#define dprint(file, line, function, ...)  { char t[DLOG_MAXLEN]; snprintf(t, sizeof(t), __VA_ARGS__); fprintf(stderr, "%6d %-32s l%4d: %s", (int) getpid(), function, line, t); }
#define DLOG(switch, ...) if (switch) dprint(__FILE__, __LINE__,__FUNCTION__,__VA_ARGS__) ;	
