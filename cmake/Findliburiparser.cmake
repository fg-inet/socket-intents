# - Find Liburiparser
# Find Liburiparser headers and library
#
#  Liburiparser_FOUND             - True if liburiparser is found.
#  Liburiparser_INCLUDE_DIRS      - Directory where liburiparser headers are located.
#  Liburiparser_LIBRARIES         - Liburiparser libraries to link against.


# Copyright (c) 2014, Theresa Enghardt <theresa@someserver.de>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.


FIND_PATH(LIBURIPARSER_INCLUDE_DIR uriparser/Uri.h)
FIND_LIBRARY(LIBURIPARSER_LIBRARY uriparser)

SET(LIBURIPARSER_LIBRARIES ${LIBURIPARSER_LIBRARY})
SET(LIBURIPARSER_INCLUDE_DIRS ${LIBURIPARSER_INCLUDE_DIR})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Liburiparser DEFAULT_MSG  LIBURIPARSER_INCLUDE_DIR LIBURIPARSER_LIBRARY)

MARK_AS_ADVANCED( LIBURIPARSER_INCLUDE_DIR LIBURIPARSER_LIBRARY )
