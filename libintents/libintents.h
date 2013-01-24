/*
 * Extension to the socket library, extending the API to support intents
 * Usage: Overload some API calls by running a program with LD_PRELOAD=libintents.so option
 *
 * Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>
 *
 */

/* Exported Functions */
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

/* 
 * Socket level for setsockopt(2)
 * Socket options on this level, implemented in libintents.so.1.0
 */
#define SOL_INTENTS 300

#define SO_CATEGORY 1	// Traffic category
#define SO_FILESIZE 2	// (Estimated) number of bytes transferred by the application
#define SO_DURATION 3	// (Estimated) time between first and last packet of the flow in seconds
#define SO_BITRATE 4	// (Estimated) size divided by duration in bytes per second
#define SO_BURSTINESS 5	// Burstiness category
#define SO_TIMELINESS 6 // Timeliness category
#define SO_RESILIENCE 7	// Resilience category

typedef enum category 
{
	C_QUERY, 			// Small, short
	C_BULKTRANSFER, 	// Large, short, fast, bursty
	C_CONTROLTRAFFIC,	// Large, long, slow, bursty
	C_KEEPALIVES,		// Small, long, slow, not bursty
	C_STREAM			// Large, long, fast, not bursty
} category_t;

typedef enum burstiness
{
	B_RANDOMBURSTS,
	B_REGULARBURSTS,
	B_NOBURSTS,
	B_BULK				// Congestion window limited
} burstiness_t;

typedef enum timeliness
{
	T_STREAM,			// Low delay, low jitter
	T_INTERACTIVE,		// Low delay, possible jitter
	T_TRANSFER,			// Should complete eventually
	T_BACKGROUNDTRAFFIC	// Only loose time constraint
} timeliness_t;

typedef enum resilience
{
	R_SENSITIVE,		// Connection loss makes application fail
	R_TOLERANT,			// Connection loss is tolerable, but inconvenient
	R_RESILIENT			// Connection loss is acceptable
} resilience_t;
