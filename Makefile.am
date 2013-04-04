AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CFLAGS =-g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE
LDADD = $(libevent_LIBS) $(glib2_LIBS) $(LIBLTDL)

AM_CFLAGS += $(libevent_CFLAGS) $(glib2_CFLAGS) 

noinst_LIBRARIES = libmuacc.a

libmuacc_a_SOURCES = clib/muacc.c clib/muacc_util.c clib/muacc_ctx.c clib/muacc_tlv.c clib/muacc.h clib/muacc_types.h clib/muacc_util.h clib/muacc_ctx.h clib/muacc_tlv.h

include_HEADERS = libintents/libintents.h clib/muacc.h

noinst_LTLIBRARIES = libmuacc_intents.la
libmuacc_intents_la_SOURCES = clib/muacc.c clib/muacc_util.c clib/muacc_ctx.c clib/muacc_tlv.c clib/muacc.h clib/muacc_util.h clib/muacc_ctx.h clib/muacc_tlv.h
libmuacc_intents_la_CFLAGS = -DUSE_SO_INTENTS $(AM_CFLAGS)

lib_LTLIBRARIES = libintents.la policy_sample.la
libintents_la_SOURCES = libintents/libintents.c
libintents_la_LIBADD = $(glib2_LIBS) -ldl libmuacc_intents.la

policy_sample_la_SOURCES = mam/policy_sample.c
policy_sample_la_LDFLAGS = -module -avoid-version

bin_PROGRAMS = mamma muacsocksd addrinfo 

muacsocksd_SOURCES = muacsocks/muacsocksd.c
muacsocksd_LDADD = $(LDADD) libmuacc.a

addrinfo_SOURCES = tests/addrinfo.c
addrinfo_LDADD = $(LDADD) libmuacc.a


mamma_SOURCES = $(clib_SOURCES) mam/mam_master.c mam/mam_ctx.c mam/mam_util.c mam/mam_iface.c mam/mam.h mam/mam_util.h
mamma_CFLAGS = $(LTDLINCL) $(AM_CFLAGS)
mamma_LDADD = $(LDADD) libmuacc.a
mamma_LDFLAGS = -export-dynamic

TESTS = testmuacc tests/policy_test.sh
check_PROGRAMS = testmuacc test_policy_generic

testmuacc_SOURCES = tests/testmuacc.c tests/test_util.h tests/test_util.c
testmuacc_LDADD = $(LDADD) libmuacc_intents.la

test_policy_generic_SOURCES = tests/test_policy_generic.c tests/test_util.h tests/test_util.c
test_policy_generic_LDADD = $(LDADD) libmuacc_intents.la

dist_noinst_SCRIPTS = autogen.sh
