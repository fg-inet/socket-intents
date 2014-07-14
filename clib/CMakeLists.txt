
ADD_LIBRARY(muacc-client SHARED muacc_client.c muacc_client_util.c)
TARGET_LINK_LIBRARIES(muacc-client muacc uriparser)

INSTALL(TARGETS muacc-client
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)

INSTALL(FILES muacc_client.h muacc_client_util.h
    DESTINATION include/libmuacc-client
)
