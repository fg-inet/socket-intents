#ifndef MUACC_CLIENT_ADDRINFO_H
#define MUACC_CLIENT_ADDRINFO_H

/** \file  client_addrinfo.h
 *  \brief BSD-like API with extended getaddrinfo
 *
 *  \copyright Copyright 2013-2017 Philipp S. Tiesel, Theresa Enghardt,
 *  Mirko Palmer, and Tobias Kaiser.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *	Implements a version of getaddrinfo that can take additional hints, like
 *  socket options (e.g., Intents), and a local address to bind to. This
 *  information is then used to, e.g., pick the right DNS server, or reorder
 *  the returned IP addresses by preference.
 */


#include "client_util.h"

/** Extended version of the standard library's struct addrinfo
 *
 *  This is used both as hint and as result from the muacc_ai_getaddrinfo
 *  function. This structure differs from struct addrinfo only in the three
 *  members ai_bindaddrlen, ai_bindaddr and ai_socketopt.
 */
struct muacc_addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    
    /** Not included in struct addrinfo. This attribute serves two functions:
      * 1. If the structure is given to muacc_ai_getaddrinfo as hints,
      *    you can give intents to the muacc master, which could have an impact
      *    on the sockopts and bind address that the master will then recommend.
      * 2. The recommended socket options from the muacc master will be returned
      *    through this attribute.
      */
    struct socketopt *ai_sockopts; 

    int ai_addrlen;
    struct sockaddr *ai_addr; 
    char *ai_canonname;

    /** Not included in struct addrinfo.
      * Length of ai_bindaddr.
      */
    int ai_bindaddrlen;
    /** Not included in struct addrinfo.
      * Contains the address, which the muacc master recommends us to bind to.
      */
    struct sockaddr *ai_bindaddr;

    struct muacc_addrinfo *ai_next;
};

/** Extended version of the standard library's getaddrinfo.
 *
 *  Basic behavior is the same as with the function in the standard library,
 *  the only difference is the additional data that can be supplied and
 *  returned through the extended struct muacc_addrinfo.
 *
 *  At the moment, this function will always return zero or one
 *  muacc_addrinfos as result, never more than one.
 */
int muacc_ai_getaddrinfo(const char *hostname, const char *service,
    const struct muacc_addrinfo *hints, struct muacc_addrinfo **result);

/** This is freeaddrinfo for struct muacc_addrinfo
  * 
  * This function has to be used instead of the system's freeaddrinfo to
  * free a struct muacc_addrinfo.
  */
void muacc_ai_freeaddrinfo(struct muacc_addrinfo *ai);

/** Applies a set of recommended sockopts to an actual socket.
  * The struct socketopts was probably returned through the ai_socketopts
  * member attribute of the struct muacc_addrinfo result of
  * muacc_ai_getaddrinfo.
  */
int muacc_ai_setsockopts(int fd, struct socketopt *sockopts);

/** Make a copy of a struct socketopt, which was obtained through
  * muacc_ai_getaddrinfo.
  * 
  * The copy needs to be freed throgh muacc_ai_freesockopts.
  */
struct socketopt *muacc_ai_clonesockopts(struct socketopt *sockopts);

/** Free a previously through muacc_ai_clonesocketopts created copy of a
  * struct socketopt.
  *
  * _Do not_ use this on sockopts directly obtained from muacc_ai_getaddrinfo.
  * Freeaddrinfo is the right function to free an entire struct muacc_addrinfo!
  */
void muacc_ai_freesockopts(struct socketopt *sockopts);

/** muacc_ai_simple_connect combines the calls to setsockopt, bind and connect,
  * which were recommended by the muacc_master, in one function.
  *
  * This initializes the socket as blocking. This function itself is potentially
  * blocking, as it calls connect on a blocking socket.
  */
int muacc_ai_simple_connect(int fd, struct muacc_addrinfo *ai);

/** muacc_ai_simple_connect_a combines the calls to setsockopt, bind and connect,
  * which were recommended by the muacc_master, in one function.
  *
  * The _a means that this function initializes the socket as non blocking
  * (for asynchronous access).
  */
int muacc_ai_simple_connect_a(int fd, struct muacc_addrinfo *ai);

#endif