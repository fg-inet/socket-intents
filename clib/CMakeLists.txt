
ADD_LIBRARY(muacc-client SHARED muacc_client.c muacc_client_util.c)
TARGET_LINK_LIBRARIES(muacc-client muacc pthread)

INSTALL(TARGETS muacc-client
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)

INSTALL(FILES muacc_client.h muacc_client_util.h muacc_util.h muacc.h strbuf.h dlog.h
    DESTINATION include/libmuacc-client
)
