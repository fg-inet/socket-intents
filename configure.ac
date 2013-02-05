AC_INIT([muacc], [0.0.1], [philipp@net.t-labs.tu-berlin.de], [muacc])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 no-define subdir-objects])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([sys/un.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([errno.h])

AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_MEMBER([struct sockaddr.sa_len],
 		[ AC_DEFINE(HAVE_SOCKADDR_LEN, 1, [Do we have sockaddr.sa_len?]) ],
 		[],
 		[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([netinet6/in6.h])

AC_ARG_ENABLE(intents, AS_HELP_STRING([--enable-intents],[enable intents socket options]))
if test "$enable_intents" != ""
then
	AC_DEFINE_UNQUOTED(USE_SO_INTENTS, 1, "Enable intents socket options")
fi

AC_ARG_VAR(MUACC_SOCKET, [specify path for MAM socket])
if test "$MUACC_SOCKET" != ""
then
	AC_DEFINE_UNQUOTED(MUACC_SOCKET, $MUACC_SOCKET, "Socket location")
else
	AC_DEFINE_UNQUOTED(MUACC_SOCKET, "/tmp/muacc.socket", "Socket location")
fi

AC_DEFINE(SOCKSD_NOISY_DEBUG, 1, "Print a lot of debugging messages in the socks daemon")

AC_DEFINE(CLIB_IF_NOISY_DEBUG, 1, "Print a lot of debugging messages in the client library interface code")
AC_DEFINE(CLIB_CTX_NOISY_DEBUG, 1, "Print a lot of debugging messages in the client library context code")
AC_DEFINE(CLIB_TLV_NOISY_DEBUG, 1, "Print a lot of debugging messages in the client library tlv code")
AC_DEFINE(CLIB_UTIL_NOISY_DEBUG, 1, "Print a lot of debugging messages in the client library utility code")



AC_OUTPUT
