/** \file test_socketconnect.c
 *  \brief Test utility for high-level socketconnect API and its policies
 *
 *	This test utility requests a new socket via the socketconnect call, which results in a
 *	socketconnect_request being sent. It succeeds if there is an answer and a socket can be
 *	set up accordingly.
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

#include "lib/muacc.h"
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"
#include "lib/muacc_util.h"

#include "lib/dlog.h"

#include "clib/muacc_client_util.h"

#include "test_util.h"

#ifndef TEST_POLICY_NOISY_DEBUG0
#define TEST_POLICY_NOISY_DEBUG0 1
#endif

#ifndef TEST_POLICY_NOISY_DEBUG1
#define TEST_POLICY_NOISY_DEBUG1 1
#endif

#ifndef TEST_POLICY_NOISY_DEBUG2
#define TEST_POLICY_NOISY_DEBUG2 1
#endif

int verbose = 1;

void print_usage(char *argv[], void *args[]);

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
    struct arg_int *arg_protocol, *arg_filesize;
    arg_protocol = arg_int0(NULL, "protocol", "<n>", "Explicitly set \"protocol\" for socket creation");
    arg_filesize = arg_int0("F", "filesize", "<n>", "Set INTENT Filesize to this value");

    struct arg_str *arg_url, *arg_transport, *arg_category;
    arg_url = arg_str0("u", "url", "<url>", "Remote URL to connect to");
    arg_transport = arg_str0(NULL, "transport", "TCP|UDP", "Set transport protocol to use (default: TCP)");
    arg_category = arg_str0("C", "category", "QUERY|BULKTRANSFER|CONTROLTRAFFIC|STREAM", "Set INTENT Category to this value");

	struct arg_lit *arg_verbose, *arg_quiet;
    arg_verbose = arg_lit0("v", "verbose", "Verbose output (Print socket contexts before and after every request");
    arg_quiet = arg_lit0("q", "quiet", "Quiet output (Do not print socket contexts before and after every request");

    struct arg_end *end = arg_end(10);

    void *argtable[] = {arg_verbose, arg_quiet, arg_url, arg_protocol, arg_transport, arg_filesize, arg_category, end};

    /* Check arguments table for errors */
    if (arg_nullcheck(argtable) != 0)
    {
        printf("Error creating argument table\n");
        print_usage(argv, argtable);
        return -1;
    }

    /* Initialize default values for arguments */
    arg_protocol->ival[0] = 0;

    *arg_transport->sval = "TCP";
    *arg_url->sval = "www.maunz.org";

    arg_filesize->ival[0] = -1;
    *arg_category->sval = NULL;

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

    intent_category_t category = -1;

    if (strncmp(*arg_transport->sval, "UDP", 4) == 0)
        socktype = SOCK_DGRAM;
    else if (strncmp(*arg_transport->sval, "TCP", 4) != 0)
    {
        printf("Invalid Transport Protocol requested - defaulting to TCP\n");
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

	int our_socket = -1;
	int returnvalue = -1;

	returnvalue = socketconnect(&our_socket, *arg_url->sval, NULL, family, socktype, *arg_protocol->ival);

    if (returnvalue == -1)
	{
		printf("Failed to create and connect the socket!\n");
        return -1;
	}

	char *buf = "testblah";
	
	returnvalue = write(our_socket, buf, sizeof(buf));

    arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));

    if (returnvalue == -1)
	{
		printf("Failed to write text on the socket!\n");
        return -1;
	}
    else
        return 0;
}
