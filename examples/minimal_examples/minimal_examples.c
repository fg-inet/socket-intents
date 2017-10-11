/** \file minimal_examples.c
 *
 *  \copyright Copyright 2013-2017 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include "muacc_client.h"
#include "client_addrinfo.h"
#include "intents.h"

#define LENGTH_OF_DATA 1048576
#define DESTINATIONHOST "example.org"
#define DESTINATIONPORT "80"

void classic_api();

void getaddrinfo_api();

void socketconnect_api();

/* Implementation starts here */

void classic_api() {

printf("Using classic BSD Socket Intents API to connect to %s...\n", DESTINATIONHOST);
// Create and initialize a context to retain information across function calls
muacc_context_t ctx;
muacc_init_context(&ctx);

int socket = -1;

struct addrinfo *result = NULL;

// Initialize a buffer of data to send later.
char buf[LENGTH_OF_DATA];
memset(&buf, 0, LENGTH_OF_DATA);

// Set Socket Intents for this connection. Note that the "socket" is still
// invalid, but it does not yet need to exist at this time. The Socket Intents
// prototype just sets the Intent within the muacc_context data structure.

enum intent_category category = INTENT_BULKTRANSFER;
muacc_setsockopt(&ctx, socket, SOL_INTENTS,
    INTENT_CATEGORY, &category, sizeof(enum intent_category));

int filesize = LENGTH_OF_DATA;
muacc_setsockopt(&ctx, socket, SOL_INTENTS,
    INTENT_FILESIZE, &filesize, sizeof(int));


// Resolve a host name. This involves a request to the MAM, which can
// automatically choose a suitable local interface or other parameters for the
// DNS request and set other parameters, such as preferred address family or
// transport protocol.
muacc_getaddrinfo(&ctx, DESTINATIONHOST, DESTINATIONPORT, NULL, &result);

// Create the socket with the address family, type, and protocol obtained by
// getaddrinfo.
socket = muacc_socket(&ctx, result->ai_family, result->ai_socktype,
    result->ai_protocol);

// Connect the socket to the remote endpoint as determined by getaddrinfo.
// This involves another request to MAM, which may at this point, e.g., choose
// to bind the socket to a local IP address before connecting it.
muacc_connect(&ctx, socket, result->ai_addr, result->ai_addrlen);

// Send data to the remote host over the socket.
write(socket, &buf, LENGTH_OF_DATA);

// Close the socket. This de-initializes any data that was stored within the
// muacc_context.
muacc_close(&ctx, socket);

printf("Done with classic BSD Socket Intents API.\n\n");
}

void getaddrinfo_api() {

printf("Using getaddrinfo Socket Intents API to connect to %s...\n", DESTINATIONHOST);
// Define Intents to be set later
enum intent_category category = INTENT_BULKTRANSFER;
int filesize = LENGTH_OF_DATA;

struct socketopt intents = { .level = SOL_INTENTS, .optname = INTENT_CATEGORY, .optval = &category, .next = NULL};
struct socketopt filesize_intent = { .level = SOL_INTENTS, .optname = INTENT_FILESIZE, .optval = &filesize, .next = NULL};

intents.next = &filesize_intent;

// Initialize a buffer of data to send later.
char buf[LENGTH_OF_DATA];
memset(&buf, 0, LENGTH_OF_DATA);

// Initialize the data structure that contains Socket Intents and other hints
struct muacc_addrinfo intent_hints = { .ai_flags = 0,
    .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = 0,
    .ai_sockopts = &intents, .ai_addr = NULL, .ai_addrlen = 0,
    .ai_bindaddr = NULL, .ai_bindaddrlen = 0, .ai_next = NULL };

struct muacc_addrinfo *result = NULL;

muacc_ai_getaddrinfo(DESTINATIONHOST, DESTINATIONPORT, &intent_hints,
    &result);

// Create and connect the socket, using the information obtained through
// getaddrinfo
int fd;
fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
muacc_ai_simple_connect(fd, result);

// Send data to the remote host over the socket, then close it.
write(fd, &buf, LENGTH_OF_DATA);
close(fd);

muacc_ai_freeaddrinfo(result);
printf("Done with getaddrinfo Socket Intents API.\n\n");
}

void socketconnect_api() {

printf("Using socketconnect API to connect to %s...\n", DESTINATIONHOST);

// Define Intents to be set later
enum intent_category category = INTENT_BULKTRANSFER;
int filesize = LENGTH_OF_DATA;

struct socketopt intents = { .level = SOL_INTENTS, .optname = INTENT_CATEGORY, .optval = &category, .next = NULL};
struct socketopt filesize_intent = { .level = SOL_INTENTS, .optname = INTENT_FILESIZE, .optval = &filesize, .next = NULL};

intents.next = &filesize_intent;

// Initialize a buffer of data to send later.
char buf[LENGTH_OF_DATA];
memset(&buf, 0, LENGTH_OF_DATA);

int socket = -1;

// Get a socket that is connected to the given host and service,
// with the given Intents
socketconnect(&socket, DESTINATIONHOST, sizeof(DESTINATIONHOST), DESTINATIONPORT, 2, &intents, AF_INET, SOCK_STREAM, 0);

// Send data to the remote host over the socket.
write(socket, &buf, LENGTH_OF_DATA);

// Close the socket and tear down the data structure kept for it
// in the library
socketclose(socket);
printf("Done with socketconnect API.\n\n");
}

int main() {

classic_api();

getaddrinfo_api();

socketconnect_api();

}
