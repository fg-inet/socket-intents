#include <unistd.h>
#define dprint(file, line, function, ...)  { char *t; asprintf(&t, __VA_ARGS__); fprintf(stderr, "%6d %-20s l%4d: %s", (int) getpid(), function, line, t); free(t); } 
#define DLOG(switch, ...) if (switch) dprint(__FILE__, __LINE__,__FUNCTION__,__VA_ARGS__) ;	
