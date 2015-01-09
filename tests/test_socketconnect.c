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
#include <pthread.h>

#include "argtable2.h"

#include "clib/muacc.h"
#include "clib/muacc_util.h"
#include "lib/muacc_ctx.h"
#include "lib/muacc_tlv.h"

#include "clib/dlog.h"

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

void cleanup(void *argtable, struct socketopt *options);

struct test_worker_args {
	int socket;
	const char *url;
  int family;
  int socktype;
	int protocol;
  socketopt_t *options;
	int times;
  int clearsocket;
	int thread_id;
};

void *test_worker (void *args);
int test_run (int *our_socket, const char* url, socketopt_t *options, int family, int socktype, int protocol, int clearsocket, int tid);

void print_usage(char *argv[], void *args[])
{
        printf("\nUsage:\n");
        printf("\t%s", argv[0]);
        arg_print_syntaxv(stdout, args, "\n");
        printf("\n");
        arg_print_glossary(stdout, args, "\t%-25s %s\n");
        printf("\n");
}

void cleanup(void *argtable, struct socketopt *options)
{
	if (argtable != NULL)
		arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));
	
	if (options != NULL)
		muacc_free_socket_option_list(options);
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

	struct arg_int *arg_times;
	arg_times = arg_int0("t", "times", "<n>", "Call socketconnect this many times");
	
	struct arg_int *arg_threads;
	arg_threads = arg_int0("p", "threads", "<n>", "Spawn threads in parallel");

	struct arg_lit *arg_verbose, *arg_quiet, *arg_clearsocket;
    arg_verbose = arg_lit0("v", "verbose", "Verbose output (Print socket contexts before and after every request");
    arg_quiet = arg_lit0("q", "quiet", "Quiet output (Do not print socket contexts before and after every request");
    arg_clearsocket = arg_lit0(NULL, "clearsocket", "When calling socketconnect multiple times, always clear the socket file descriptor");

    struct arg_end *end = arg_end(10);

    void *argtable[] = {arg_verbose, arg_quiet, arg_times, arg_threads, arg_clearsocket, arg_url, arg_protocol, arg_transport, arg_filesize, arg_category, end};

    /* Check arguments table for errors */
    if (arg_nullcheck(argtable) != 0)
    {
        printf("Error creating argument table\n");
        print_usage(argv, argtable);
        return -1;
    }

    /* Initialize default values for arguments */
		arg_times->ival[0] = 4;
    arg_threads->ival[0] = 4;
    arg_protocol->ival[0] = 0;
		

    *arg_transport->sval = "TCP";
    *arg_url->sval = "http://www.maunz.org:443";

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

    if (strncmp(*arg_transport->sval, "UDP", 4) == 0)
        socktype = SOCK_DGRAM;
    else if (strncmp(*arg_transport->sval, "TCP", 4) != 0)
    {
        printf("Invalid Transport Protocol requested - defaulting to TCP\n");
    }

    intent_category_t category = -1;

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

	socketopt_t *options = NULL;

	if (category != -1)
	{
		printf("setting intent category\n");
		if (0 != muacc_set_intent(&options, INTENT_CATEGORY, &category, sizeof(category), 0))
		{
			printf("Failed to set Intent Category\n");
			return -1;
		}
	}

	if (arg_filesize->ival[0] != -1)
	{
		printf("setting intent filesize\n");
		if (0 != muacc_set_intent(&options, INTENT_FILESIZE, arg_filesize->ival, sizeof(arg_filesize->ival[0]), 0))
		{
			printf("Failed to set Intent Category\n");
			return -1;
		}
	}

	printf("Socket options:\n");
	_muacc_print_socket_option_list(options);

	int our_socket = -1;

	printf("================================================\n");

	if(arg_threads->ival[0] <= 0) {

		printf("Doing sequential tests without threads:\n");
		
		int ret = -1;
		
		for (int try = 0; try < arg_times->ival[0]; try++)
		{
			ret = test_run (&our_socket, *arg_url->sval, options, family, socktype, *arg_protocol->ival, (arg_clearsocket->count > 0), 0);

			if (ret != 0) {
				printf("Try #%d: FAILED - exiting\n", try+1);
				break;
			} else {
				printf("Try #%d: OK\n", try+1);
			}
		}
		if (our_socket != -1)
		{
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Clearing and closing socket %d\n", our_socket);
			socketconnect_close(our_socket);
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Socket closed.\n");
		}
		
	} else {
				
		int ret = -1;
		
		ret = test_run (&our_socket, *arg_url->sval, options, family, socktype, *arg_protocol->ival, (arg_clearsocket->count > 0), 0);
		
		if (ret != 0) {
			printf("Initial Try FAILED - exiting\n");
			goto main_abort;
		} else {
			printf("Initial Try OK\n");
		}

		printf("================================================\n");

		printf("Spawning threads:");

		struct test_worker_args targs;
		targs.socket = our_socket;
		targs.url = *arg_url->sval;
		targs.family = family;
		targs.socktype = socktype;
		targs.protocol = *arg_protocol->ival;
		targs.options = NULL;
		targs.times = arg_times->ival[0];
		targs.clearsocket = (arg_clearsocket->count > 0);
	
		pthread_t *thread = malloc(sizeof(pthread_t) * arg_threads->ival[0]);

		int t;	

		for(t = 1; t<=arg_threads->ival[0]; t++)
		{
			struct test_worker_args *cargs = malloc(sizeof(struct test_worker_args));
			memcpy(cargs, &targs, sizeof(struct test_worker_args));
			cargs->thread_id = t;
			cargs->options = _muacc_clone_socketopts(options);
		
			pthread_create(&thread[t], NULL, test_worker, (void *) cargs);
		
			printf(" %d", t);
		}
		printf(" done\n");

		printf("================================================\n");


		for(t = 0; t<arg_threads->ival[0]; t++)
		{
			void *status;
			pthread_join(thread[t], &status); 
		}	
	
		printf("================================================\n");
	
		printf("All threads terminated.\n");

	}	
	
	main_abort:

	cleanup(argtable, options);
	return 0;
	
}

void *test_worker (void *argp) {

	struct test_worker_args *args = (struct test_worker_args *) argp;
	int our_socket = args->socket;
	int try = 0;
	int ret = -1;

	for (try = 0; try < args->times; try++)
	{

			ret = test_run ( &(args->socket), args->url, args->options, args->family, args->socktype, args->protocol, args->clearsocket, args->thread_id);
			if (ret != 0) {
				printf("Thread %d Try #%d: FAILED - exiting\n", args->thread_id, try+1);
				goto exit_test_worker;
			} else {
				printf("Thread %d Try #%d: OK\n", args->thread_id, try+1);
			}

	}

	printf("Thread %d done\n", args->thread_id);
	ret = 0;

	exit_test_worker:

	if (args->socket != -1)
	{
		DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Finished - trying to close socket %d\n", args->thread_id, args->socket);
		socketconnect_close(args->socket);
		DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Closed socket %d \n", args->thread_id, args->socket);
	}
	_muacc_free_socketopts(args->options);
	free(argp);
	
	DLOG(TEST_POLICY_NOISY_DEBUG0, "Thread %d: Exiting\n", args->thread_id);
  pthread_exit((void*) ret);
}

int test_run (int *our_socket, const char* url, socketopt_t *options, int family, int socktype, int protocol, int clearsocket, int tid) {
	DLOG(TEST_POLICY_NOISY_DEBUG0, "Thread %d: Starting test run\n", tid);
	int returnvalue = -1;
	
	DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Socketconnect with %d\n", tid, *our_socket);
	returnvalue = socketconnect(our_socket, url, options, family, socktype, protocol);
	DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Socketconnect returned code %d, socket %d\n", tid, returnvalue, *our_socket);

	if (returnvalue == -1)
	{
		perror("Failed to create and connect the socket:");
		return -1;
	}

	char *buf = "testblah";
	
	DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Writing teststring to socket %d\n", tid, *our_socket);
	returnvalue = write(*our_socket, buf, sizeof(buf));
	DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Writing returned value %d, trying to release socket %d now\n", tid, returnvalue, *our_socket);
	socketconnect_release(*our_socket);
	DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Released socket %d\n", tid, *our_socket);

	if (returnvalue == -1)
	{
		perror("Failed to write text on the socket:");
		return -1;
	}

	if (clearsocket > 0) 
	{	
		if (*our_socket != -1)
		{
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Clearing and closing socket %d\n", tid, *our_socket);
			socketconnect_close(*our_socket);
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Socket closed.\n", tid);
		}
		*our_socket = -1; // Clearing socket
	}

	return 0;
	
}

