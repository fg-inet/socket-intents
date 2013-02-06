AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CFLAGS =-g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE
AM_LDFLAGS =

AM_CFLAGS += $(libevent_CFLAGS) $(glib2_CFLAGS) 
AM_LDFLAGS += $(libevent_LIBS) $(glib2_LIBS)

bin_PROGRAMS = mamma muacsocksd addrinfo 

clib_SOURCES  = clib/muacc.c clib/muacc.h
clib_SOURCES += clib/muacc_util.c clib/muacc_util.h
clib_SOURCES += clib/muacc_ctx.c clib/muacc_ctx.h
clib_SOURCES += clib/muacc_tlv.c clib/muacc_tlv.h

muacsocksd_SOURCES = $(clib_SOURCES) muacsocks/muacsocksd.c 
addrinfo_SOURCES = $(clib_SOURCES) tests/addrinfo.c 
mamma_SOURCES = $(clib_SOURCES) mam/mam_master.c 


dist_noinst_SCRIPTS = autogen.sh
