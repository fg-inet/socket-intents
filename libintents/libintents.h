/*
 * Extension to the socket library, extending the API to support intents
 * Usage: Overload some API calls by running a program with LD_PRELOAD=libintents.so option
 *
 * Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>
 *
 */

/* Exported Functions */
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

