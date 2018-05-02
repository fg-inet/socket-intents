# Copyright notice for the files copied from
# http://www.opensync.org/browser/branches/3rd-party-cmake-modules/modules
# Author: Joerg Mayer
# $Id$

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:

# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# $Id$
#
# - Find pcap and winpcap
# Find the native PCAP includes and library
#
#  PCAP_INCLUDE_DIRS - where to find pcap.h, etc.
#  PCAP_LIBRARIES    - List of libraries when using pcap.
#  PCAP_FOUND        - True if pcap found.

find_path( PCAP_INCLUDE_DIR
  NAMES
  pcap/pcap.h
  pcap.h
  HINTS
    "${PCAP_HINTS}/include"
)

find_library( PCAP_LIBRARY
  NAMES
    pcap
    wpcap
  HINTS
    "${PCAP_HINTS}/lib"
)


include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( PCAP DEFAULT_MSG PCAP_INCLUDE_DIR PCAP_LIBRARY )

if( PCAP_FOUND )
  set( PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR} )
  set( PCAP_LIBRARIES ${PCAP_LIBRARY} )
else()
  set( PCAP_INCLUDE_DIRS )
  set( PCAP_LIBRARIES )
endif()

#Functions
include( CMakePushCheckState )
include( CheckFunctionExists )
include( CheckVariableExists )

cmake_push_check_state()
set( CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIRS} )
set( CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} )

check_function_exists( "pcap_open_dead" HAVE_PCAP_OPEN_DEAD )
check_function_exists( "pcap_freecode" HAVE_PCAP_FREECODE )
#
# Note: for pcap_breakloop() and pcap_findalldevs(), the autoconf script
# checks for more than just whether the function exists, it also checks
# for whether pcap.h declares it; Mac OS X software/security updates can
# update libpcap without updating the headers.
#
check_function_exists( "pcap_breakloop" HAVE_PCAP_BREAKLOOP )
check_function_exists( "pcap_create" HAVE_PCAP_CREATE )
check_function_exists( "pcap_datalink_name_to_val" HAVE_PCAP_DATALINK_NAME_TO_VAL )
check_function_exists( "pcap_datalink_val_to_description" HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION )
check_function_exists( "pcap_datalink_val_to_name" HAVE_PCAP_DATALINK_VAL_TO_NAME )
check_function_exists( "pcap_findalldevs" HAVE_PCAP_FINDALLDEVS )
check_function_exists( "pcap_free_datalinks" HAVE_PCAP_FREE_DATALINKS )
check_function_exists( "pcap_get_selectable_fd" HAVE_PCAP_GET_SELECTABLE_FD )
check_function_exists( "pcap_lib_version" HAVE_PCAP_LIB_VERSION )
check_function_exists( "pcap_list_datalinks" HAVE_PCAP_LIST_DATALINKS )
check_function_exists( "pcap_set_datalink" HAVE_PCAP_SET_DATALINK )
check_function_exists( "bpf_image" HAVE_BPF_IMAGE )
# Remote pcap checks
check_function_exists( "pcap_open" H_PCAP_OPEN )
check_function_exists( "pcap_findalldevs_ex" H_FINDALLDEVS_EX )
check_function_exists( "pcap_createsrcstr" H_CREATESRCSTR )
if( H_PCAP_OPEN AND H_FINDALLDEVS_EX AND H_CREATESRCSTR )
  set( HAVE_PCAP_REMOTE 1 )
  set( HAVE_REMOTE 1 )
endif()

cmake_pop_check_state()

mark_as_advanced( PCAP_LIBRARIES PCAP_INCLUDE_DIRS )