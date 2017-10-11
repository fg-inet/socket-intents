
ADD_LIBRARY(muacc-client SHARED muacc_client.c client_socketapi.c client_util.c client_socketconnect_async.c client_addrinfo.c client_socketconnect_emulated.c client_socketconnect.c)
TARGET_LINK_LIBRARIES(muacc-client muacc pthread)

INSTALL(TARGETS muacc-client
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)

INSTALL(FILES
	client_socketapi.h client_socketconnect.h client_util.h client_socketconnect_async.h client_addrinfo.h
	client_socketconnect_emulated.h muacc_client.h
    DESTINATION include/muacc
)
