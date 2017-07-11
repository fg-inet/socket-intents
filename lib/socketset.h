/** \file  socketset.h
 *  \brief Helper functions for handling socket sets
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#ifndef MUACC_LIB_SOCKETSET_H
#define MUACC_LIB_SOCKETSET_H

/** List of socketsets that we have
 *  each with its own destination host/port, connection type, status, read/write lock
 *  and list of sockets that belong to the set
 */
typedef struct socketset
{
	pthread_rwlock_t lock;		/**< Read/Write lock for this set */
	pthread_rwlock_t destroylock;/**< Lock for deleting this set */
	uint8_t	use_count;			/**< Number of sockets in this set that are in use */
	char   *host;				/**< Host name for this socket set */
	size_t  hostlen;			/**< Length of host name in bytes (without \0) */
	char   *serv;				/**< Destination port or service for this socket set */
	size_t  servlen;			/**< Length of service in bytes (without \0) */
	int 	type;				/**< Connection type, e.g. SOCK_STREAM or SOCK_DGRAM */
	int		socketchoose_pending;/**< Used by the asynchronous API instead of the locks to determine if a socketchoose request is pending with this set. */
	struct  socketlist *sockets;/**< List of sockets within this socket set */
	struct	socketset *next;
} socketset_t;

/** List of sockets that are part of a socket set
 *  each with its own file descriptor, context, and status
 */
typedef struct socketlist
{
	int		file;				/**< File descriptor of this socket */
	int		flags;              /**< Flags indicating the status of this socket, e.g. MUACC_SOCKET_IN_USE */
	struct	_muacc_ctx *ctx;	/**< Context of this socket */
	struct socketlist 	*next;
} socketlist_t;


#define MUACC_SOCKET_IN_USE 0x01

/* socketlist lock */
#ifndef CLIB_IF_LOCKS
#define CLIB_IF_LOCKS 0
#endif

/** Find the socketset struct from a given file descriptor
 *
 * @return The corresponding socketset
 */
struct socketlist *_muacc_socketlist_find_file (struct socketlist *slist, int socket);
/** Add socket to a socketset
 *
 * @return 0 on success, a negative number otherwise
 */
struct socketset* _muacc_add_socket_to_set(struct socketset **list_of_sets, int socket, struct _muacc_ctx *ctx);

/** Find the socket set that contains the socket with the given file descriptor, if any
 *
 * @return Pointer to the socket set that contains the socket, if found, or NULL
 */
struct socketset *_muacc_find_socketset(struct socketset *list_of_sets, int socket);

/** Find a socket set that matches the socket context
 *
 * @return Pointer to the socket set if found, or NULL
 */
struct socketset *_muacc_find_set_for_socket(struct socketset *list_of_sets, struct _muacc_ctx *ctx);

/** Find socketset that is a duplicate of the given one (i.e. has different file descriptor but same context)
 * 
 *  @return next duplicate socket set, or NULL if none exists
 */
struct socketlist *_muacc_socketset_find_dup (struct socketlist *slist);

/** Find the previous socket set in the list
 *
 * @return Pointer to the previous socket set (or NULL, if this is the first set in the list)
 */
struct socketset *_muacc_find_prev_socketset(struct socketset **list_of_sets, struct socketset *set);

/** Remove socket from set, and clean up socketset if set is now empty
 *
 * @return 0 on success, -1 otherwise
 */
int _muacc_remove_socket_from_list (struct socketset **list_of_sets, int socket);

/** Clean up unused sockets from a socket set
 *
 * @return 0 on success, -1 otherwise
 */
int _muacc_cleanup_sockets(struct socketset **set);

/** Free a socket from a socket set, and close its file descriptor.
 *
 *  @return 0 on success (set still has sockets), 1 on success (set is empty now), -1 otherwise
 */
int _muacc_free_socket(struct socketset *set_to_delete, struct socketlist *list_to_delete, struct socketlist *prevlist);

/** Print the list of socket sets
 *  Warning - difference to previous version of muacc_print_socketsetlist is that
 *  no locking is done (as locking mechanisms differ from API to API),
 *  so this function is possibly not thread-safe.
 */
void muacc_print_socketsetlist(struct socketset *list_of_sets);

/** Print a socket set
 *  Warning - difference to previous version of muacc_print_socketset is that
 *  no locking is done (as locking mechanisms differ from API to API),
 *  so this function is possibly not thread-safe.
 */
void muacc_print_socketset(struct socketset *set);

#endif
