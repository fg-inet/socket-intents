ADD_EXECUTABLE(muacsocksd muacsocksd.c)
TARGET_LINK_LIBRARIES(muacsocksd muacc-client)

INSTALL(TARGETS muacsocksd
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
