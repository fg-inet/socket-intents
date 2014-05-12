# - Find libnl
#
# This module defines
#  LIBNL_LIBRARIES - the libnl libraries
#  LIBNL_INCLUDE_DIR - the include path of the libnl and libgenl libraries

find_library (LIBNL_LIBRARY nl-3)
find_library (LIBNL_GENERIC_LIBRARY nl-genl-3)

if ( ${LIBNL_LIBRARY} MATCHES "LIBNL_LIBRARY-NOTFOUND")
	message( STATUS "Compiling without libnl - Not Found." )
	SET (LIBNL_GENERIC_LIBRARY "")
	SET (LIBNL_INCLUDE_DIR "")
	SET (LIBNL_LIBRARY "")
	SET (NETLINK_CODE "")
else ( ${LIBNL_LIBRARY} MATCHES "LIBNL_LIBRARY-NOTFOUND")
	SET (NETLINK_CODE "mam_netlink.c")
	SET (HAVE_LIBNL 1)
endif ( ${LIBNL_LIBRARY} MATCHES "LIBNL_LIBRARY-NOTFOUND")

set(LIBNL_LIBRARIES 
	${LIBNL_LIBRARY} 
	${LIBNL_GENERIC_LIBRARY}
)



find_path (LIBNL_INCLUDE_DIR
  NAMES
  netlink/netlink.h
  PATH_SUFFIXES
  libnl3
)
