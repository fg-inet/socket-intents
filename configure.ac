AC_INIT([muacc], [0.0.1], [philipp@net.t-labs.tu-berlin.de], [muacc])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 no-define subdir-objects])
AC_PROG_CC
AM_PROG_CC_C_O
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_ARG_WITH(muacc_socket, [  --with-muacc-socket            set socket path])
if test "$muacc_socket" != ""
then
	AC_DEFINE_UNQUOTED(MUACC_SOCKET, $muacc_socket, "Socket location")
else
	AC_DEFINE_UNQUOTED(MUACC_SOCKET, "/tmp/muacc.socket", "Socket location")
fi

AC_DEFINE(CLIB_NOISY_DEBUG, 1, "Print a lot of debugging messages in the client library")
AC_DEFINE(SOCKSD_NOISY_DEBUG, 0, "Print a lot of debugging messages in the socks daemin")


AC_OUTPUT