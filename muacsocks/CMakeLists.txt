ADD_EXECUTABLE(muacsocksd muacsocksd.c)
TARGET_LINK_LIBRARIES(muacsocksd clib)

INSTALL(TARGETS muacsocksd
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
