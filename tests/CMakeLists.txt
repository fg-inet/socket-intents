INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIR})
ADD_EXECUTABLE(policytest EXCLUDE_FROM_ALL test_policy_generic.c test_util.c)
TARGET_LINK_LIBRARIES(policytest muacc-client ${GLIB2_LIBRARIES} argtable2)

ADD_TEST(policytest ${CMAKE_CURRENT_BINARY_DIR}/policytest)

