AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CFLAGS = -fPIC -g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE
AM_YFLAGS = -d -v --debug --verbose

LDADD = $(libevent_LIBS) $(glib2_LIBS) $(LIBLTDL)

AM_CFLAGS += $(libevent_CFLAGS) $(glib2_CFLAGS) 

BUILT_SOURCES = mam/mam_configp.h

include_HEADERS = lib/intents.h

lib_LTLIBRARIES = libmuacc_client.la
noinst_LIBRARIES = libmuacc.a
bin_PROGRAMS = mamma muacsocksd addrinfo
pkglib_LTLIBRARIES = policy_sample.la policy_intents.la policy_filesize.la #policy_rr_naive.la

mammaconfdir=$(sysconfdir)/mamma
mammaconf_DATA = mamma-rr-naive.conf mamma-sample.conf

libmuacc_a_SOURCES = lib/muacc_ctx.h lib/muacc_tlv.h lib/muacc_util.h lib/dlog.h lib/strbuf.h lib/muacc_ctx.c lib/muacc_tlv.c lib/muacc_util.c lib/strbuf.c
libmuacc_a_CFLAGS = -DUSE_SO_INTENTS $(AM_CFLAGS)

libmuacc_client_la_SOURCES = clib/muacc_client.h clib/muacc_client_util.h clib/muacc_client.c clib/muacc_client_util.c
libmuacc_client_la_CFLAGS = -DUSE_SO_INTENTS $(AM_CFLAGS)
libmuacc_client_la_LIBADD = libmuacc.a


muacsocksd_SOURCES = muacsocks/muacsocksd.c
muacsocksd_LDADD = $(LDADD) libmuacc_client.la

addrinfo_SOURCES = tests/addrinfo.c
addrinfo_LDADD = $(LDADD) libmuacc_client.la

mamma_SOURCES = mam/mam_master.c mam/mam_ctx.c mam/mam_util.c mam/mam_iface.c mam/mam_configp.y mam/mam_configs.l mam/mam.h mam/mam_util.h
mamma_CFLAGS = $(LTDLINCL) $(AM_CFLAGS)
mamma_LDADD = $(LDADD) libmuacc.a
mamma_LDFLAGS = -export-dynamic

policy_la_LDFLAGS = -module -avoid-version

policy_sample_la_SOURCES = policies/policy_sample.c policies/policy_util.h policies/policy_util.c
policy_sample_la_LDFLAGS = $(policy_la_LDFLAGS)

policy_rr_naive_la_SOURCES = policies/policy_rr_naive.c
policy_rr_naive_la_LDFLAGS = $(policy_la_LDFLAGS)

policy_filesize_la_SOURCES = policies/policy_filesize.c policies/policy_util.h policies/policy_util.c
policy_filesize_la_LDFLAGS = $(policy_la_LDFLAGS)

policy_intents_la_SOURCES = policies/policy_intents.c policies/policy_util.h policies/policy_util.c
policy_intents_la_LDFLAGS = $(policy_la_LDFLAGS)
policy_intents_la_LIBADD = libmuacc.a

TESTS = testmuacc tests/policy_test.sh
check_PROGRAMS = testmuacc test_policy_generic

testmuacc_SOURCES = tests/testmuacc.c tests/test_util.h tests/test_util.c
testmuacc_LDADD = $(LDADD) libmuacc.a libmuacc_client.la

test_policy_generic_SOURCES = tests/test_policy_generic.c tests/test_util.h tests/test_util.c
test_policy_generic_LDADD = $(LDADD) libmuacc.a libmuacc_client.la

dist_noinst_SCRIPTS = autogen.sh
