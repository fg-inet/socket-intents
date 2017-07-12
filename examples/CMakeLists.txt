ADD_SUBDIRECTORY(addrinfo_demo)
ADD_SUBDIRECTORY(muacsocks)

ADD_SUBDIRECTORY(socketconnect_async_demo)
ADD_SUBDIRECTORY(synchr_socketconnect_demo)

# At the moment we need to build the demos separately after we installed libmuacc-client system-wide.
set_target_properties(socketconnect_async_demo addrinfo_demo synchr_socketconnect_demo PROPERTIES EXCLUDE_FROM_ALL 1 EXCLUDE_FROM_DEFAULT_BUILD 1)

ADD_SUBDIRECTORY(curl-multi)
