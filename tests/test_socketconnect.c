/** \file test_socketconnect.c
 *  \brief Test utility for high-level socketconnect API and its policies
 *
 *	This test utility requests a new socket via the socketconnect call, which results in a
 *	new socketset being created. It subsequently makes some more writes on the socket while calling
 *	socketconnect again, getting the same socket back, or a different one from the set.
 *	The test succeeds if it is always able to send its data to the socket it has been given.
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
#include "uriparser/Uri.h"

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

#define HOSTNAME_LEN_LIMIT 2000
#define SERVICE_LEN_LIMIT 100

void print_usage(char *argv[], void *args[]);

void cleanup(void *argtable, struct socketopt *options);

struct test_worker_args {
	int socket;
	const char *host;
	size_t hostlen;
	const char *serv;
	size_t servlen;
  int family;
  int socktype;
	int protocol;
  socketopt_t *options;
	int times;
  int clearsocket;
	int thread_id;
};

void *test_worker (void *args);
int test_run (int *our_socket, const char* host, size_t hostlen, const char* serv, size_t servlen, socketopt_t *options, int family, int socktype, int protocol, int clearsocket, int tid);

int parse_url_to_host_and_serv(const char *url, char **hostname, size_t *hostnamelen, char **serv, size_t *servlen);

int parse_url_to_host_and_serv(const char *url, char **hostname, size_t *hostnamelen, char **serv, size_t *servlen)
{
	if (url == NULL)
	{
		DLOG(TEST_POLICY_NOISY_DEBUG1, "Cannot parse NULL URL!\n");
		return -1;
	}

	if (hostnamelen == NULL || servlen == NULL)
	{
		DLOG(TEST_POLICY_NOISY_DEBUG1, "Cannot proceed with hostnamelen or servlen NULL!\n");
		return -1;
	}

	DLOG(TEST_POLICY_NOISY_DEBUG2, "Parsing URL %s\n", url);
	UriParserStateA state;
	UriUriA uri;

	state.uri = &uri;
	if ((uriParseUriA(&state, url) != URI_SUCCESS) || (uri.hostText.first == NULL || uri.portText.first == NULL))
	{
		/* Failed to parse URL */
		DLOG(TEST_POLICY_NOISY_DEBUG1, "Failed to parse URL: %s (Does it contain a protocol, hostname, and port?)\n", url);
		uriFreeUriMembersA(&uri);
		return -1;
	}

	*hostnamelen = uri.hostText.afterLast - uri.hostText.first;
	*servlen = uri.portText.afterLast - uri.portText.first;

	*hostname = malloc(*hostnamelen + 1);
	*serv = malloc(*servlen + 1);

	if (*hostnamelen == 0 || *servlen == 0 || *hostname == NULL || *serv == NULL)
	{
		DLOG(TEST_POLICY_NOISY_DEBUG1, "Error when parsing %s or allocating memory for results\n", url);
		uriFreeUriMembersA(&uri);
		return -1;
	}

	*hostname = strncpy(*hostname, uri.hostText.first, *hostnamelen);
	(*hostname)[*hostnamelen] = 0;

	*serv = strncpy(*serv, uri.portText.first, *servlen);
	(*serv)[*servlen] = 0;

	DLOG(TEST_POLICY_NOISY_DEBUG2, "Successfully parsed URL: Hostname = %s, Service = %s\n", *hostname, *serv);
	uriFreeUriMembersA(&uri);
	return 0;
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

    struct arg_str *arg_url, *arg_hostname, *arg_service, *arg_transport, *arg_category;
    arg_url = arg_str0("u", "url", "<url>", "Remote URL to connect to");
    arg_hostname = arg_str0("h", "hostname", "<hostname>", "Remote hostname to connect to");
    arg_service = arg_str0("s", "service", "<servname>|<port>", "Remote service or port to connect to");
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

    void *argtable[] = {arg_verbose, arg_quiet, arg_times, arg_threads, arg_clearsocket, arg_url, arg_hostname, arg_service, arg_protocol, arg_transport, arg_filesize, arg_category, end};

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
		
	*arg_hostname->sval = NULL;
	*arg_service->sval = NULL;
    *arg_transport->sval = "TCP";
    *arg_url->sval = "http://www.maunz.org:443";

	char *hostname = NULL;
	size_t hostnamelen = 0;
	char *serv = NULL;
	size_t servlen = 0;

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

	if (*arg_hostname->sval != NULL && *arg_service->sval != NULL)
	{
		DLOG(TEST_POLICY_NOISY_DEBUG2, "Got hostname = %s and service = %s -- copying.\n", *arg_hostname->sval, *arg_service->sval);
		hostname = (char *)*arg_hostname->sval;
		hostnamelen = strnlen(*arg_hostname->sval, HOSTNAME_LEN_LIMIT);
		serv = (char *)*arg_service->sval;
		servlen = strnlen(*arg_service->sval, SERVICE_LEN_LIMIT);
	}
	else
	{
		DLOG(TEST_POLICY_NOISY_DEBUG2, "Got no hostname and service -- parsing.\n");
		if (0 != parse_url_to_host_and_serv(*arg_url->sval, &hostname, &hostnamelen, &serv, &servlen))
		{
			DLOG(TEST_POLICY_NOISY_DEBUG1, "Parsing failed!\n");
			return -1;
		}
	}

	if (hostname == NULL || serv == NULL)
	{
		printf("Failed to find a valid host name or service -- aborting.\n");
		return -1;
	}
	else
	{
		DLOG(TEST_POLICY_NOISY_DEBUG2, "Hostname = %s, Service = %s.\n", hostname, serv);
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
			ret = test_run (&our_socket, hostname, hostnamelen, serv, servlen, options, family, socktype, *arg_protocol->ival, (arg_clearsocket->count > 0), 0);

			if (ret != 0) {
				printf("Try #%d: FAILED - exiting\n", try+1);
				break;
			} else {
				printf("Try #%d: OK\n", try+1);
				if (try+1 < arg_times->ival[0])
				{
					// Release socket if this is not the last run
					if (0 != socketrelease(our_socket))
					{
						DLOG(TEST_POLICY_NOISY_DEBUG1, "Releasing socket %d failed.\n", our_socket);
					}
					else
					{
						DLOG(TEST_POLICY_NOISY_DEBUG2, "Released socket %d.\n", our_socket);
					}
					if (our_socket != -1)
					{
						// Varying the parameters a bit
						hostname = NULL;
						hostnamelen = 0;
						serv = NULL;
						servlen = NULL;
						family = 0;
						socktype = 0;
					}
				}
			}
		}
		if (our_socket != -1)
		{
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Clearing and closing socket %d\n", our_socket);
			socketclose(our_socket);
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Socket closed.\n");
		}
		
	} else {
				
		int ret = -1;

		ret = test_run (&our_socket, hostname, hostnamelen, serv, servlen, options, family, socktype, *arg_protocol->ival, (arg_clearsocket->count > 0), 0);
		
		if (ret != 0) {
			printf("Initial Try FAILED - exiting\n");
			goto main_abort;
		} else {
			if (0 != socketrelease(our_socket))
			{
				DLOG(TEST_POLICY_NOISY_DEBUG1, "Releasing socket %d failed.\n", our_socket);
			}
			else
			{
				DLOG(TEST_POLICY_NOISY_DEBUG2, "Released socket %d.\n", our_socket);
			}
			printf("Initial Try OK\n");
		}

		printf("================================================\n");

		printf("Spawning threads:");

		struct test_worker_args targs;
		targs.socket = our_socket;
		targs.host = hostname;
		targs.hostlen = hostnamelen;
		targs.serv = serv;
		targs.servlen = servlen;
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


		for(t = 1; t<=arg_threads->ival[0]; t++)
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
	int try = 0;
	int ret = -1;

	for (try = 0; try < args->times; try++)
	{
		if (try != 0 && args->socket != -1)
		{
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Testing with socket %d and NULL parameters\n", args->thread_id, args->socket);
			ret = test_run ( &(args->socket), NULL, 0, NULL, 0, args->options, 0, 0, 0, args->clearsocket, args->thread_id);
		}
		else
		{
			ret = test_run ( &(args->socket), args->host, args->hostlen, args->serv, args->servlen, args->options, args->family, args->socktype, args->protocol, args->clearsocket, args->thread_id);
		}
		if (ret != 0) {
			DLOG(TEST_POLICY_NOISY_DEBUG1, "Thread %d: Test run with socket %d failed, exiting\n", args->thread_id, args->socket);
			printf("Thread %d Try #%d: FAILED - exiting\n", args->thread_id, try+1);
			goto exit_test_worker;
		} else {
			if (try+1 < args->times)
			{
				// Release socket if this is not the last run
				if (0 != socketrelease(args->socket))
				{
					DLOG(TEST_POLICY_NOISY_DEBUG1, "Thread %d: Releasing socket %d failed.\n", args->thread_id, args->socket);
				}
				else
				{
					DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Released socket %d.\n", args->thread_id, args->socket);
				}
			}
			printf("Thread %d Try #%d: OK\n", args->thread_id, try+1);
		}

	}

	printf("Thread %d done\n", args->thread_id);
	ret = 0;

	exit_test_worker:

	if (args->socket != -1)
	{
		DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Finished - trying to close socket %d\n", args->thread_id, args->socket);
		if (socketclose(args->socket) == 0)
		{
			DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Closed socket %d \n", args->thread_id, args->socket);
		}
		else
		{
			DLOG(TEST_POLICY_NOISY_DEBUG1, "Thread %d: Failed to close socket %d \n", args->thread_id, args->socket);
		}
	}
	_muacc_free_socketopts(args->options);
	free(argp);
	
	DLOG(TEST_POLICY_NOISY_DEBUG0, "Thread %d: Exiting\n", args->thread_id);
  pthread_exit((void*) ret);
}

int test_run (int *our_socket, const char* host, size_t hostlen, const char *serv, size_t servlen, socketopt_t *options, int family, int socktype, int protocol, int clearsocket, int tid) {
	int returnvalue = -1;
	
	DLOG(TEST_POLICY_NOISY_DEBUG0, "Thread %d: Starting test run: Socketconnect with %d\n", tid, *our_socket);
	returnvalue = socketconnect(our_socket, host, hostlen, serv, servlen, options, family, socktype, protocol);
	DLOG(TEST_POLICY_NOISY_DEBUG0, "Thread %d: Socketconnect returned code %d, socket %d\n", tid, returnvalue, *our_socket);

	if (returnvalue == -1)
	{
		perror("Failed to create and connect the socket:");
		return -1;
	}

	char *buf = "testblah";
	
	DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Writing teststring to socket %d\n", tid, *our_socket);
	returnvalue = write(*our_socket, buf, sizeof(buf));
	DLOG(TEST_POLICY_NOISY_DEBUG2, "Thread %d: Writing on socket %d returned value %d\n", tid, *our_socket, returnvalue);

	if (returnvalue < 0)
	{
		DLOG(TEST_POLICY_NOISY_DEBUG1, "Thread %d: Failed to write to socket %d \n", tid, *our_socket);
		perror("Failed to write text on the socket:");
		return -1;
	}

	return 0;
	
}

