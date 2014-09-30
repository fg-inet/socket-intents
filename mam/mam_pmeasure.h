#include "mam.h"

void pmeasure_setup();
void pmeasure_callback(evutil_socket_t fd, short what, void *arg);
void pmeasure_cleanup();

void pmeasure_print_summary(void *pfx, void *data);
