/** \file   intents.h
 *  \brief 	Definition of intent sockopts
 *  		NOT intended to provide any guarantees or quality of service of any kind.
 *
 *  Intents are additional information about the expected characteristics and needs of an application's
 *  traffic that is expected to flow through the particular socket.
 *  Intents are supported by the multi access framework (libmuacc_client).
 *
 *  Disclaimer: None of these options provide a GUARANTEE of an improvement. Intents are strictly
 *  best-effort.
 *
 *  Usage: After creating a socket, set socket options on SOL_SOCKET level, documented below.
 */

#ifndef __INTENTS_H__
#define __INTENTS_H__

/** Socket level for setsockopt() call
 *
 *  These socket options are stored in a muacc context when used with libmuacc_client
 */
#define SOL_INTENTS 300

#define INTENT_CATEGORY 1	/**< Traffic category */
#define INTENT_FILESIZE 2	/**< (Estimated) Number of bytes transferred by the application */
#define INTENT_DURATION 3	/**< (Estimated) Time between first and last packet of the flow in seconds */
#define INTENT_BITRATE 4	/**< (Estimated) Size divided by duration in bytes per second */
#define INTENT_BURSTINESS 5	/**< Burstiness category */
#define INTENT_TIMELINESS 6 /**< Timeliness category */
#define INTENT_RESILIENCE 7	/**< Resilience category */

/** One of five brief categories into which the traffic may fit
 */
typedef enum intent_category
{
	INTENT_QUERY, 			/**< Small, short */
	INTENT_BULKTRANSFER, 	/**< Large, short, fast, bursty */
	INTENT_CONTROLTRAFFIC,	/**< Large, long, slow, bursty */
	INTENT_KEEPALIVES,		/**< Small, long, slow, not bursty */
	INTENT_STREAM			/**< Large, long, fast, not bursty */
} intent_category_t;

/** Qualitative description of the application traffic's behavior regarding bursts.
 *
 *  May influence the chosen congestion control algorithm in stream sockets.
 */
typedef enum intent_burstiness
{
	INTENT_RANDOMBURSTS,
	INTENT_REGULARBURSTS,
	INTENT_NOBURSTS,
	INTENT_BULK				/**< Congestion window limited */
} intent_burstiness_t;

/** Desired characteristics regarding delay and jitter.
 */
typedef enum intent_timeliness
{
	INTENT_STREAMING,			/**< Low delay, low jitter */
	INTENT_INTERACTIVE,			/**< Low delay, possible jitter */
	INTENT_TRANSFER,			/**< Should complete eventually */
	INTENT_BACKGROUNDTRAFFIC	/**< Only loose time constraint */
} intent_timeliness_t;

/** Impact on the application if an established connection fails (assuming it can be reestablished)
 *
 *  May influence an application's decision to use techniques to make the connection more
 *  stable, e.g. Mobile IP in scenarios where a client may roam to other networks, thus reducing
 *  the risk of having to terminate and reestablish the connection.
 */
typedef enum intent_resilience
{
	INTENT_SENSITIVE,		/**< Connection loss makes application fail */
	INTENT_TOLERANT,			/**< Connection loss is tolerable, but inconvenient */
	INTENT_RESILIENT			/**< Connection loss is acceptable */
} intent_resilience_t;

#endif
