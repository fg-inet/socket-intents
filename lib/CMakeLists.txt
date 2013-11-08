ADD_LIBRARY(muacc SHARED muacc_ctx.c  muacc_tlv.c  muacc_util.c strbuf.c)

INSTALL(TARGETS muacc
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)
