AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CFLAGS = -g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE

bin_PROGRAMS = muacsocksd addrinfo

clib_SOURCES  = clib/muacc.c clib/muacc.h
clib_SOURCES += clib/muacc_util.c clib/muacc_util.h
clib_SOURCES += clib/muacc_ctx.c clib/muacc_ctx.h
clib_SOURCES += clib/muacc_tlv.c clib/muacc_tlv.h

muacsocksd_SOURCES = $(clib_SOURCES) muacsocks/muacsocksd.c 
addrinfo_SOURCES = $(clib_SOURCES) tests/addrinfo.c 

dist_noinst_SCRIPTS = autogen.sh
