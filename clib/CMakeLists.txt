
ADD_LIBRARY(muacc-client SHARED muacc_client.c client_util.c)
TARGET_LINK_LIBRARIES(muacc-client muacc pthread)

INSTALL(TARGETS muacc-client
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)

INSTALL(FILES muacc_client.h client_util.h
    DESTINATION include/muacc
)
