# - Find Libevent
# Find Libevent headers and library
#
#  Libevent_FOUND             - True if liblzma is found.
#  Libevent_INCLUDE_DIRS      - Directory where liblzma headers are located.
#  Libevent_LIBRARIES         - Lzma libraries to link against.


# Copyright (c) 2013, Alexander Couzens, <lynxis@fe80.eu>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.


FIND_PATH(LIBEVENT_INCLUDE_DIR event.h )
FIND_LIBRARY(LIBEVENT_LIBRARY event)

SET(LIBEVENT_LIBRARIES ${LIBEVENT_LIBRARY})
SET(LIBEVENT_INCLUDE_DIRS ${LIBEVENT_INCLUDE_DIR})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Libevent DEFAULT_MSG  LIBEVNET_INCLUDE_DIR LIBEVENT_LIBRARY)

MARK_AS_ADVANCED( LIBEVENT_INCLUDE_DIR LIBEVENT_LIBRARY )
