AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CFLAGS =-g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE
LDADD = $(libevent_LIBS) $(glib2_LIBS)

AM_CFLAGS += $(libevent_CFLAGS) $(glib2_CFLAGS) 

noinst_LIBRARIES = libmuacc.a

libmuacc_a_SOURCES = clib/muacc.c clib/muacc_util.c clib/muacc_ctx.c clib/muacc_tlv.c clib/muacc.h clib/muacc_util.h clib/muacc_ctx.h clib/muacc_tlv.h

include_HEADERS = libintents/libintents.h clib/muacc.h

lib_LTLIBRARIES = libintents.la
libintents_la_SOURCES = libintents/libintents.c
libintents_la_LIBADD = $(glib2_LIBS) -ldl libmuacc.a

bin_PROGRAMS = muacsocksd addrinfo

muacsocksd_SOURCES = muacsocks/muacsocksd.c
muacsocksd_LDADD = $(LDADD) libmuacc.a

addrinfo_SOURCES = tests/addrinfo.c
addrinfo_LDADD = $(LDADD) libmuacc.a


dist_noinst_SCRIPTS = autogen.sh
