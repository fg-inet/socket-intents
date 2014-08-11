INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIR})

ADD_EXECUTABLE(socketconnecttest EXCLUDE_FROM_ALL test_socketconnect.c test_util.c)
TARGET_LINK_LIBRARIES(socketconnecttest muacc-client ${GLIB2_LIBRARIES} argtable2)

ADD_TEST(socketconnecttest_query_filesize ${CMAKE_CURRENT_BINARY_DIR}/socketconnecttest --category QUERY --filesize 1024)
