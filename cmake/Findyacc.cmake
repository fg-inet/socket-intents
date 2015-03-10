find_program(YACC_EXE
    NAMES
        bison
        yacc
)
if(YACC_EXE STREQUAL "YACC_EXE-NOTFOUND")
    message(FATAL_ERROR "dear user, plase install yacc/bison!")
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
