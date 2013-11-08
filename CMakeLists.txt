cmake_minimum_required(VERSION 2.6)

PROJECT(muacc C)
ADD_DEFINITIONS(-Os -Wall --std=gnu99 -g3 -Wmissing-declarations)
ADD_DEFINITIONS(-DGNU_SOURCE)

ADD_DEFINITIONS(-DMUACC_SOCKET="/tmp/muacc")
# AM_CFLAGS = -fPIC -g --pedantic -Wall -std=c99 -O0 -D_GNU_SOURCE
# AM_YFLAGS = -d -v --debug --verbose

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

# for glib2
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "/usr/share/apps/cmake/modules/")
# for libevent
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
FIND_PACKAGE(GLIB2 REQUIRED)

FIND_PACKAGE(libevent REQUIRED)

ADD_SUBDIRECTORY(clib)
ADD_SUBDIRECTORY(lib)
ADD_SUBDIRECTORY(mam)
ADD_SUBDIRECTORY(muacsocks)
