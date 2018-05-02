INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIR})

ADD_EXECUTABLE(socketconnecttest EXCLUDE_FROM_ALL test_socketconnect.c test_util.c)
TARGET_LINK_LIBRARIES(socketconnecttest muacc-client ${GLIB2_LIBRARIES} argtable2 pthread gcc_s uriparser)

ADD_EXECUTABLE(policytest EXCLUDE_FROM_ALL test_policy_generic.c test_util.c)
TARGET_LINK_LIBRARIES(policytest muacc-client ${GLIB2_LIBRARIES} argtable2 pthread gcc_s)

ADD_TEST(socketconnecttest ${CMAKE_CURRENT_BINARY_DIR}/socketconnecttest -F 1024)
