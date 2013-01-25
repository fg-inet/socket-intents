/** \file libintents.h
 *  \brief 	Headers and definitions for the socket intents library -
 *  		Does NOT provide any guarantees or quality of service of any kind.
 *
 *  Socket library that is intended to overload some socket API calls to support intents,
 *  i.e. additional information about the expected characteristics and needs of an application's
 *  traffic that is expected to flow through the particular socket.
 *
 *  Disclaimer: None of these options provide a GUARANTEE of an improvement. Intents are strictly
 *  best-effort.
 *
 *  Usage: After creating a socket, set socket options on SOL_SOCKET level, documented below.
 *	Run the application with LD_PRELOAD=./libintents.so environment variable.
 */

/* Exported Functions */
int socket(int domain, int type, int protocol);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

/** Socket level for setsockopt() call
 *
 *  Only socket options on this level are handled by the intents library.
 *  All other socket options are passed to the original setsockopt function.
 */
#define SOL_INTENTS 300

/* Socket options on this level, implemented in libintents.so.1.0*/
#define SO_CATEGORY 1	/**< Traffic category */
#define SO_FILESIZE 2	/**< (Estimated) Number of bytes transferred by the application */
#define SO_DURATION 3	/**< (Estimated) Time between first and last packet of the flow in seconds */
#define SO_BITRATE 4	/**< (Estimated) Size divided by duration in bytes per second */
#define SO_BURSTINESS 5	/**< Burstiness category */
#define SO_TIMELINESS 6 /**< Timeliness category */
#define SO_RESILIENCE 7	/**< Resilience category */

/** One of five brief categories into which the traffic may fit
 */
typedef enum category
{
	C_QUERY, 			/**< Small, short */
	C_BULKTRANSFER, 	/**< Large, short, fast, bursty */
	C_CONTROLTRAFFIC,	/**< Large, long, slow, bursty */
	C_KEEPALIVES,		/**< Small, long, slow, not bursty */
	C_STREAM			/**< Large, long, fast, not bursty */
} category_s;

/** Qualitative description of the application traffic's behavior regarding bursts.
 *
 *  May influence the chosen congestion control algorithm in stream sockets.
 */
typedef enum burstiness
{
	B_RANDOMBURSTS,
	B_REGULARBURSTS,
	B_NOBURSTS,
	B_BULK				/**< Congestion window limited */
} burstiness_s;

/** Desired characteristics regarding delay and jitter.
 */
typedef enum timeliness
{
	T_STREAM,			/**< Low delay, low jitter */
	T_INTERACTIVE,		/**< Low delay, possible jitter */
	T_TRANSFER,			/**< Should complete eventually */
	T_BACKGROUNDTRAFFIC	/**< Only loose time constraint */
} timeliness_s;

/** Impact on the application if an established connection fails (assuming it can be reestablished)
 *
 *  May influence an application's decision to use techniques to make the connection more
 *  stable, e.g. Mobile IP in scenarios where a client may roam to other networks, thus reducing
 *  the risk of having to terminate and reestablish the connection.
 */
typedef enum resilience
{
	R_SENSITIVE,		/**< Connection loss makes application fail */
	R_TOLERANT,			/**< Connection loss is tolerable, but inconvenient */
	R_RESILIENT			/**< Connection loss is acceptable */
} resilience_s;
