find_program(LEX_EXE
    flex
)
if(LEX_EXE STREQUAL "LEX_EXE-NOTFOUND")
    message(FATAL_ERROR "dear user, plase install flex!")
endif(LEX_EXE STREQUAL "LEX_EXE-NOTFOUND")

find_program(YACC_EXE
    bison
)
if(YACC_EXE STREQUAL "YACC_EXE-NOTFOUND")
    message(FATAL_ERROR "dear user, plase install bison!")
endif(YACC_EXE STREQUAL "YACC_EXE-NOTFOUND")

# reuseable cmake macro for yacc
MACRO(YACC_FILE _filename)
    GET_FILENAME_COMPONENT(_basename ${_filename} NAME_WE)
    ADD_CUSTOM_COMMAND(
        OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c
                ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.h
        COMMAND ${YACC_EXE} ${YACC_FLAGS} -d
                --output=${_basename}.c
                ${CMAKE_CURRENT_SOURCE_DIR}/${_filename}
        DEPENDS ${_filename}
    )
ENDMACRO(YACC_FILE)

# reuseable cmake macro for lex
MACRO(LEX_FILE _filename)
    GET_FILENAME_COMPONENT(_basename ${_filename} NAME_WE)
    ADD_CUSTOM_COMMAND(
        OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c
        COMMAND ${LEX_EXE}
                -o${_basename}.c
                ${CMAKE_CURRENT_SOURCE_DIR}/${_filename}
        DEPENDS ${_filename} )
ENDMACRO(LEX_FILE)

SET(YACC_FLAGS -d -v --debug --verbose)

INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${LIBEVENT_INCLUDE_DIR})

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
YACC_FILE(mam_configp.y)
LEX_FILE(mam_configs.l)

ADD_EXECUTABLE(mam mam_configp.c mam_configs.c mam_ctx.c mam_iface.c  mam_util.c mam_master.c)
TARGET_LINK_LIBRARIES(mam muacc y ltdl ${LIBEVENT_LIBRARIES} ${GLIB2_LIBRARIES})

INSTALL(TARGETS mam
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

ADD_SUBDIRECTORY(policies)
