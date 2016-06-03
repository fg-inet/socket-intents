# - Find libnl
#
# This module defines
#  LIBNL_LIBRARIES - the libnl libraries
#  LIBNL_INCLUDE_DIR - the include path of the libnl and libgenl libraries

find_library (LIBNL_LIBRARY nl-3)
find_library (LIBNL_GENERIC_LIBRARY nl-genl-3)
find_library (LIBNL_ROUTE_LIBRARY nl-route-3)
find_library (LIBNL_DIAG_LIBRARY nl-idiag-3)

if (   ${LIBNL_LIBRARY} MATCHES "LIBNL_LIBRARY-NOTFOUND" 
	OR ${LIBNL_GENERIC_LIBRARY} MATCHES "LIBNL_GENERIC_LIBRARY-NOTFOUND" 
	OR ${LIBNL_ROUTE_LIBRARY} MATCHES "LIBNL_ROUTE_LIBRARY-NOTFOUND" 
	OR ${LIBNL_DIAG_LIBRARY} MATCHES "LIBNL_DIAG_LIBRARY-NOTFOUND")
	message( STATUS "Compiling without libnl* - Libraries not Found - check that libnl3, genl3, route3 and idiag3 are installed." )
	SET (LIBNL_LIBRARY "")
	SET (LIBNL_GENERIC_LIBRARY "")
	SET (LIBNL_ROUTE_LIBRARY "")
	SET (LIBNL_DIAG_LIBRARY "")
	SET (LIBNL_INCLUDE_DIR "")
	SET (NETLINK_CODE_FILES "")
else ()
	message ( STATUS "Found Lib-nl-3, nl-genl-3, nl-route-3, nl-idiag-3")
	SET (NETLINK_CODE_FILES "mam_netlink.c" "mptcp_netlink_parser.c" "mam_pmeasure.c")
	SET (HAVE_LIBNL 1)
	add_definitions( -DHAVE_LIBNL )
endif ()

set(LIBNL_LIBRARIES 
	${LIBNL_LIBRARY} 
	${LIBNL_GENERIC_LIBRARY}
	${LIBNL_ROUTE_LIBRARY}
	${LIBNL_DIAG_LIBRARY}
)

find_path (LIBNL_INCLUDE_DIR
  NAMES
  netlink/netlink.h
  PATH_SUFFIXES
  libnl3
)
