AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CFLAGS = -g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE

bin_PROGRAMS = muacsocksd addrinfo
muacsocksd_SOURCES = clib/muacc.c clib/tlv.c clib/muacc.h muacsocks/muacsocksd.c 
addrinfo_SOURCES = clib/muacc.c clib/tlv.c clib/muacc.h tests/addrinfo.c 

dist_noinst_SCRIPTS = autogen.sh
