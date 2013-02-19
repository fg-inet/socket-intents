AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CFLAGS =-g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE
LDADD = $(libevent_LIBS) $(glib2_LIBS)

AM_CFLAGS += $(libevent_CFLAGS) $(glib2_CFLAGS) 

noinst_LIBRARIES = libmuacc.a

libmuacc_a_SOURCES = clib/muacc.c clib/muacc_util.c clib/muacc_ctx.c clib/muacc_tlv.c clib/muacc.h clib/muacc_util.h clib/muacc_ctx.h clib/muacc_tlv.h

include_HEADERS = libintents/libintents.h clib/muacc.h

noinst_LTLIBRARIES = libmuacc_intents.la
libmuacc_intents_la_SOURCES = clib/muacc.c clib/muacc_util.c clib/muacc_ctx.c clib/muacc_tlv.c clib/muacc.h clib/muacc_util.h clib/muacc_ctx.h clib/muacc_tlv.h
libmuacc_intents_la_CFLAGS = -DUSE_SO_INTENTS

lib_LTLIBRARIES = libintents.la
libintents_la_SOURCES = libintents/libintents.c
libintents_la_LIBADD = $(glib2_LIBS) -ldl libmuacc_intents.la

bin_PROGRAMS = mamma muacsocksd addrinfo 

muacsocksd_SOURCES = muacsocks/muacsocksd.c
muacsocksd_LDADD = $(LDADD) libmuacc.a

addrinfo_SOURCES = tests/addrinfo.c
addrinfo_LDADD = $(LDADD) libmuacc.a


mamma_SOURCES = $(clib_SOURCES) mam/mam_master.c 
mamma_LDADD = $(LDADD) libmuacc.a

TESTS = tests/libintents.sh
check_PROGRAMS = testintents
testintents_SOURCES = tests/testintents.c

dist_noinst_SCRIPTS = autogen.sh
