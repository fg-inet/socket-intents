
ADD_LIBRARY(clib SHARED muacc_client.c muacc_client_util.c)
TARGET_LINK_LIBRARIES(clib muacc)

INSTALL(TARGETS clib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)
