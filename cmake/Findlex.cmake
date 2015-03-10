find_program(LEX_EXE
    flex
)
if(LEX_EXE STREQUAL "LEX_EXE-NOTFOUND")
    message(FATAL_ERROR "dear user, plase install flex!")
endif(LEX_EXE STREQUAL "LEX_EXE-NOTFOUND")

