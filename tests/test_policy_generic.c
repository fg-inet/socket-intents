/** \file test_policy_generic.c
 *  \brief Test utility for MAM with generic policy
 *
 *  \copyright Copyright 2013-2015 Philipp S. Tiesel, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 *
 *  This test utility opens a connection with the given parameters using the muacc socket library
 *  and thus sends a resolve_request and connect_request to the Multi Access Manager.
 *  It suceeds if there is an answer, which is then displayed.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <glib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "argtable2.h"

#include "clib/muacc.h"
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"
#include "lib/muacc_util.h"

#include "clib/dlog.h"

#include "clib/muacc_client_util.h"

#include "test_util.h"

#ifndef TEST_POLICY_NOISY_DEBUG0
#define TEST_POLICY_NOISY_DEBUG0 0
#endif

#ifndef TEST_POLICY_NOISY_DEBUG1
#define TEST_POLICY_NOISY_DEBUG1 1
#endif

#ifndef TEST_POLICY_NOISY_DEBUG2
#define TEST_POLICY_NOISY_DEBUG2 0
#endif

int verbose = 1;

/** Data structure that contains all relevant data for a getaddrinfo request
 *  To be supplied to the getaddrinfo_request test function as a parameter
 */
struct addrinfo_context
{
	char *node;
	char *service;
	struct addrinfo *hints;
};

/** Data structure that contains all relevant data for socket creation and a connect request
 *  To be supplied to the connect_request test function as a parameter
 */
struct connect_context
{
	int family;
	int socktype;
	int protocol;
	struct sockaddr *remote_addr;
	socklen_t remote_addr_len;
};

struct addrinfo_context *create_actx_localport (int family, int port);
struct addrinfo_context *create_actx_remote (int family, int port, const char *name);
struct connect_context *create_cctx(int family, int socktype, int protocol, struct sockaddr *remote_addr, socklen_t remote_addr_len);
struct connect_context *create_cctx_resolve(int family, int socktype, int protocol, int port, const char *hostname);
struct addrinfo *getaddrinfo_request(muacc_context_t *ctx, const struct addrinfo_context *actx);
int connect_request(muacc_context_t *ctx, const struct connect_context *cctx, int *sfd);
void print_usage(char *argv[], void *args[]);

/** Helper that creates an addrinfo context for a request for localhost and a given port
 */
struct addrinfo_context *create_actx_localport (int family, int port)
{
	struct addrinfo_context *actx = malloc(sizeof(struct addrinfo_context));
	memset(actx, 0, sizeof(struct addrinfo_context));

	actx->hints = malloc(sizeof(struct addrinfo));
	memset(actx->hints, 0, sizeof(struct addrinfo));

    if (family == AF_INET)
        actx->hints->ai_family = AF_INET;
    else if (family == AF_INET6)
        actx->hints->ai_family = AF_INET6;
    else
        actx->hints->ai_family = AF_UNSPEC;

	actx->hints->ai_socktype = SOCK_DGRAM;
	actx->hints->ai_flags = AI_PASSIVE;

	asprintf(&actx->service, "%d", port);

	return actx;
}

/** Helper that creates an addrinfo context for a remote host and, optionally, port
 */
struct addrinfo_context *create_actx_remote (int family, int port, const char *name)
{
	struct addrinfo_context *actx = malloc(sizeof(struct addrinfo_context));
	memset(actx, 0, sizeof(struct addrinfo_context));

	actx->hints = malloc(sizeof(struct addrinfo));
	memset(actx->hints, 0, sizeof(struct addrinfo));

    if (family == AF_INET)
        actx->hints->ai_family = AF_INET;
    else if (family == AF_INET6)
        actx->hints->ai_family = AF_INET6;
    else
        actx->hints->ai_family = AF_UNSPEC;

	actx->hints->ai_socktype = SOCK_DGRAM;

	if (name != NULL)
	{
		asprintf(&actx->node, "%s", name);
	}
	else
	{
		return NULL;
	}

	if (port != 0)
	{
		asprintf(&actx->service, "%d", port);
	}

	return actx;
}

struct connect_context *create_cctx(int family, int socktype, int protocol, struct sockaddr *remote_addr, socklen_t remote_addr_len)
{
	struct connect_context *cctx = malloc(sizeof(struct connect_context));
	memset(cctx, 0, sizeof(struct connect_context));

	cctx->family = family;
	cctx->socktype = socktype;
	cctx->protocol = protocol;

	cctx->remote_addr_len = remote_addr_len;
	cctx->remote_addr = _muacc_clone_sockaddr(remote_addr, remote_addr_len);

	return cctx;
}

/** Send a getaddrinfo resolve request to the MAM and print the context before and after
 */
struct addrinfo *getaddrinfo_request(muacc_context_t *ctx, const struct addrinfo_context *actx)
{
	if (actx == NULL) return NULL;

	struct addrinfo *result = NULL;

    if (verbose)
    {
        printf("Socket context before resolve request: \n");
        muacc_print_context(ctx);
    }

    printf("Sending resolve_request to MAM...\n\n");
	muacc_getaddrinfo(ctx, actx->node, actx->service, actx->hints, &result);

    if (verbose)
    {
        printf("Socket context after resolve request: \n");
        muacc_print_context(ctx);
    }

    return result;
}

/** Create a socket, send a connect request to the MAM and print the context before and after
 */
int connect_request(muacc_context_t *ctx, const struct connect_context *cctx, int *sfd)
{
	if (cctx == NULL) return -1;

	*sfd = muacc_socket(ctx, cctx->family, cctx->socktype, cctx->protocol);
    if (*sfd <= 0)
    {
        printf("Creating the socket failed!\n");
        return -1;
    }

    if (verbose)
    {
        printf("Socket context before connect request: \n");
        muacc_print_context(ctx);
        printf("\n");

        printf("Remote address to connect to:\n");
        _muacc_print_socket_addr(cctx->remote_addr, cctx->remote_addr_len);
        printf("\n");
    }

    printf("Sending connect_request to MAM...\n\n");
	int ret = muacc_connect(ctx, *sfd, cctx->remote_addr, cctx->remote_addr_len);

    if (verbose)
    {
        printf("Socket context after connect request: \n");
        muacc_print_context(ctx);
    }
    if (ret == 0)
        printf("Connection successful!\n");
    else
    {
        printf("Connection failed: Returned (%d): %s\n", ret, strerror(errno));
        
    }
    return ret;
}

void print_usage(char *argv[], void *args[])
{
        printf("\nUsage:\n");
        printf("\t%s", argv[0]);
        arg_print_syntaxv(stdout, args, "\n");
        printf("\n");
        arg_print_glossary(stdout, args, "\t%-25s %s\n");
        printf("\n");
}

int main(int argc, char *argv[])
{
    /* Set up command line arguments table */
    struct arg_int *arg_localport, *arg_remoteport, *arg_protocol, *arg_filesize, *arg_ipversion;
    arg_localport = arg_int0(NULL, "localport", "<n>", "Resolve a local port number");
    arg_remoteport = arg_int0("p", "remoteport", "<n>", "Connect to this remote port");
    arg_protocol = arg_int0(NULL, "protocol", "<n>", "Explicitly set \"protocol\" for socket creation");
    arg_filesize = arg_int0("F", "filesize", "<n>", "Set INTENT Filesize to this value");
    arg_ipversion = arg_int0(NULL, "ipversion", "4|6", "Set IP version (default: unspecified)");

    struct arg_str *arg_address, *arg_hostname, *arg_transport, *arg_category, *arg_message;
    arg_address = arg_str0("a", "address", "<IP address>", "Remote IP address to connect to");
	arg_message = arg_str0("m", "message", "<message>", "Message to send to Remote");
    arg_hostname = arg_str0("h", "hostname", "<hostname>", "Remote host name to resolve");
    arg_transport = arg_str0(NULL, "transport", "TCP|UDP", "Set transport protocol to use (default: TCP)");
    arg_category = arg_str0("C", "category", "QUERY|BULKTRANSFER|CONTROLTRAFFIC|STREAM", "Set INTENT Category to this value");

    struct arg_lit *arg_resolveonly, *arg_connectonly, *arg_verbose, *arg_quiet;
    arg_resolveonly = arg_lit0(NULL, "resolve-only", "Only make resolve request, do not connect");
    arg_connectonly = arg_lit0(NULL, "connect-only", "Do not make resolve request to the policy, only connect request");
    arg_verbose = arg_lit0("v", "verbose", "Verbose output (Print socket contexts before and after every request");
    arg_quiet = arg_lit0("q", "quiet", "Quiet output (Do not print socket contexts before and after every request");

    struct arg_end *end = arg_end(10);

    void *argtable[] = {arg_verbose, arg_quiet, arg_localport, arg_address, arg_message, arg_hostname, arg_remoteport, arg_ipversion, arg_protocol, arg_transport, arg_filesize, arg_category, arg_resolveonly, arg_connectonly, end};

    /* Check arguments table for errors */
    if (arg_nullcheck(argtable) != 0)
    {
        printf("Error creating argument table\n");
        print_usage(argv, argtable);
        return -1;
    }

    /* Initialize default values for arguments */
    arg_localport->ival[0] = -1;
    arg_remoteport->ival[0] = 80;
    arg_protocol->ival[0] = 0;
    arg_ipversion->ival[0] = 0;

    *arg_address->sval = NULL;
    *arg_transport->sval = "TCP";
    *arg_hostname->sval = "www.maunz.org";

    arg_filesize->ival[0] = -1;
    *arg_category->sval = NULL;
	*arg_message->sval = NULL;

    /* Parse the command line arguments */
    int nerrors = arg_parse(argc, argv, argtable);

    if (nerrors != 0)
    {
        printf("Error parsing command line arguments:\n");
        arg_print_errors(stdout, end, "policytest");
        print_usage(argv, argtable);
        return -1;
    }

    if (arg_verbose->count > 0)
    {
        verbose = 1;
    }

    if (arg_quiet->count > 0)
    {
        verbose = 0;
    }

    int family = AF_UNSPEC;
    int socktype = SOCK_STREAM;
    struct sockaddr_in addr4 = {};
    struct sockaddr_in6 addr6 = {};

    intent_category_t category = -1;

    if (*arg_ipversion->ival == 6)
        family = AF_INET6;
    else if (*arg_ipversion->ival == 4)
        family = AF_INET;

    if (strncmp(*arg_transport->sval, "UDP", 4) == 0)
        socktype = SOCK_DGRAM;
    else if (strncmp(*arg_transport->sval, "TCP", 4) != 0)
    {
        printf("Invalid Transport Protocol requested - defaulting to TCP\n");
    }

    if (*arg_address->sval != NULL)
    {
        // IP address has been set
        if (1 == inet_pton(AF_INET, *arg_address->sval, &(addr4.sin_addr)))
        {
            DLOG(TEST_POLICY_NOISY_DEBUG2, "Parsed IPv4 address successfully: %s\n", *arg_address->sval);
            addr4.sin_family = AF_INET;
        }
        else if (1 == inet_pton(AF_INET6, *arg_address->sval, &(addr6.sin6_addr)))
        {
            DLOG(TEST_POLICY_NOISY_DEBUG2, "Parsed IPv6 address successfully: %s\n", *arg_address->sval);
            addr6.sin6_family = AF_INET6;
        }
        else
        {
            printf("Address could not be parsed successfully: %s\n", *arg_address->sval);
        }
    }

    if (*arg_category->sval != NULL)
    {
        if (strncmp(*arg_category->sval, "QUERY", 6) == 0)
            category = INTENT_QUERY;
        else if (strncmp(*arg_category->sval, "BULKTRANSFER", 13) == 0)
            category = INTENT_BULKTRANSFER;
        else if (strncmp(*arg_category->sval, "CONTROLTRAFFIC", 15) == 0)
            category = INTENT_CONTROLTRAFFIC;
        else if (strncmp(*arg_category->sval, "STREAM", 7) == 0)
            category = INTENT_STREAM;
        else
            printf("Invalid Intent Category %s - Not setting category\n", *arg_category->sval);
    }
	
	printf("================================================\n");

    // Set up a new context
    muacc_context_t *ctx = malloc(sizeof(muacc_context_t));
    muacc_init_context(ctx);

    if (*arg_filesize->ival > 1)
        ctx_set_filesize(ctx->ctx, arg_filesize->ival[0]);

    if (category >= INTENT_QUERY && category <= INTENT_STREAM)
        ctx_set_category(ctx->ctx, category);

    struct addrinfo *result = NULL;
    struct connect_context *cctx = NULL;
    struct addrinfo_context *local_actx = NULL;
    struct addrinfo_context *remote_actx = NULL;
    int connect_ret = 0;
    int pretty_dots = 0;

    // Do local name resolution
    if (*arg_localport->ival > 0)
    {
        printf("Local port %d - Doing local name resolution\n", *arg_localport->ival);
        local_actx = create_actx_localport(family, *arg_localport->ival);
        getaddrinfo_request(ctx, local_actx);
    }

    if (addr4.sin_family != AF_INET && addr6.sin6_family != AF_INET6)
    {
        DLOG(TEST_POLICY_NOISY_DEBUG2, "Resolving host name %s\n", *arg_hostname->sval);
        // Remote address not already given - we need name resolution
        remote_actx = create_actx_remote(family, *arg_remoteport->ival, *arg_hostname->sval);

        // Name resolution part
        if (arg_connectonly->count > 0 )
        {
            // Do not perform resolve request - directly resolve name
            getaddrinfo(remote_actx->node, remote_actx->service, remote_actx->hints, &result);
        }
        else
        {
            // Perform resolve request
            result = getaddrinfo_request(ctx, remote_actx);
        }

        if (result == NULL)
        {
            printf("Error resolving name!\n");
            return -1;
        }
    }

    // Connect part
	int sfd;
    if (arg_resolveonly->count > 0)
    {
        printf("Resolve-only mode - not connecting.\n");
    }
    else if (result != NULL)
    {
        // Connect to the resolved address
        cctx = create_cctx(result->ai_family, result->ai_socktype, result->ai_protocol, _muacc_clone_sockaddr(result->ai_addr, result->ai_addrlen), result->ai_addrlen);
        if (cctx->remote_addr->sa_family == AF_INET)
            ((struct sockaddr_in *)cctx->remote_addr)->sin_port = htons(*arg_remoteport->ival);
        else
        if (cctx->remote_addr->sa_family == AF_INET6)
            ((struct sockaddr_in6 *)cctx->remote_addr)->sin6_port = htons(*arg_remoteport->ival);
        
        connect_ret = connect_request(ctx, cctx, &sfd);
        freeaddrinfo(result);
    }
    else if (addr4.sin_family == AF_INET)
    {
        // Connect to this IPv4 address
        addr4.sin_port = htons(*arg_remoteport->ival);
        cctx = create_cctx(AF_INET, socktype, *arg_protocol->ival, (struct sockaddr *) &addr4, sizeof(addr4));
        connect_ret = connect_request(ctx, cctx, &sfd);
    }
    else if (addr6.sin6_family == AF_INET6)
    {
        // Connect to this IPv6 address
        addr6.sin6_port = htons(*arg_remoteport->ival);
        cctx = create_cctx(AF_INET6, socktype, *arg_protocol->ival, (struct sockaddr *) &addr6, sizeof(addr6));
        connect_ret = connect_request(ctx, cctx, &sfd);
    }
	
	

	printf("================================================\n");
	
	
	if (*arg_message->sval != NULL)
	{
		if (socktype != SOCK_STREAM)
			printf("Sorry, currently sending messages is only implemented for TCP (SOCK_STREAM).\n");
		else
		{
			printf("Sending HTTP request to Remote.\n");			
			if (*arg_address->sval != NULL)
			{
				char *message;
				int len = asprintf(&message, "GET %s HTTP/1.1\r\nHost: %s\r\nAcept: */*\r\nConnection: close\r\n\r\n", *arg_message->sval, *arg_address->sval);
				send(sfd, message, len, 0);
				
				printf("message: %s\n", message);
			
				char buf[8192];
				int ret = 0, count = 0;
				do
				{
					ret = recv(sfd, buf, 8192, 0);
					usleep(20000);

                    if (++pretty_dots > 50)
                    {
					   printf(".");
                       pretty_dots = 0;
                    }
					fflush(stdout);
					count += ret;
				}
				while (ret);
				printf("\nReceived: %d bytes.\n", count);
			}
		}
	}

    // Tear down the context
    muacc_release_context(ctx);
    free(ctx);

    arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));

    if (connect_ret != 0)
        return -1;
    else
        return 0;
}
