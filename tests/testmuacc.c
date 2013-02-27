/** \file testmuacc.c
 *  \brief Set of unit tests for the muacc library
 */

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
#include "../clib/muacc.h"
#include "../clib/muacc_ctx.h"
#include "../clib/muacc_tlv.h"
#include "../clib/muacc_util.h"
#include "../libintents/libintents.h"

/** Fixture = Element used in a set of tests
 *
 */
typedef struct
{
	muacc_context_t *context;
} dfixture;

/** Helper that creates an empty muacc context
 *
 */
void ctx_empty_setup(dfixture *df, const void *test_data)
{
	printf("\n===========\n");
	muacc_context_t *newctx = malloc(sizeof(muacc_context_t));
	df->context = newctx;
	muacc_init_context(df->context);
}

/** Helper that releases a context
 *
 */
void ctx_destroy(dfixture *df, const void *test_data)
{
	muacc_release_context(df->context);
	free(df->context);
	printf("\n===========\n");
}

/** Helper that compares two lists of sockopts
 *
 */
void compare_sockopts(const struct socketopt *a, const struct socketopt *b)
{
	while (a != NULL && b != NULL)
	{
		g_assert_cmpint(a->level, ==, b->level);
		g_assert_cmpint(a->optname, ==, b->optname);
		g_assert_cmpint(a->optlen, ==, b->optlen);
		g_assert( 0 == memcmp(a->optval, b->optval, a->optlen));
		a = a->next;
		b = b->next;
	}
}

/** Trying to create a context with a NULL pointer
 *  This should return -1, but not crash the application
 */
void ctx_create_null()
{
	int ret = -2;
	ret = muacc_init_context(NULL);
	g_assert_cmpint(ret, ==, -1);
}

/** Test that prints out a context
 *
 */
void ctx_print(dfixture *df, const void *param)
{
	muacc_print_context(df->context);
}

/** Test that copies a list of sockopts
 *
 */
void sockopts_copy_valid()
{
	struct socketopt testopt = { .level = SOL_SOCKET, .optname = SO_BROADCAST, .optval=malloc(sizeof(int)), .optlen = sizeof(int) };
	int flag = 1;
	memcpy(testopt.optval, &flag, sizeof(int));

	struct socketopt testopt2 = { .level = SOL_INTENTS, .optname = SO_CATEGORY, .optval=malloc(sizeof(enum category)), .optlen = sizeof(enum category) };
	enum category cat = C_KEEPALIVES;
	memcpy(testopt2.optval, &cat, sizeof(enum category));
	testopt.next = &testopt2;

//	_muacc_print_socket_option_list((const struct socketopt *) &testopt);
	struct socketopt *newopt = NULL;
	newopt = _muacc_clone_socketopts((const struct socketopt *) &testopt);
	compare_sockopts(&testopt, newopt);
//	_muacc_print_socket_option_list((const struct socketopt *) newopt);
}

/** Add test cases to the test harness */
int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	printf("Welcome to the muacc testing functions\n");
	g_test_add("/ctx/print_empty", dfixture, NULL, ctx_empty_setup, ctx_print, ctx_destroy);
	g_test_add_func("/ctx/create_null", ctx_create_null);
	g_test_add_func("/sockopts/copy", sockopts_copy_valid);
	return g_test_run();
}
