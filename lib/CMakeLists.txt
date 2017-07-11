ADD_LIBRARY(muacc STATIC muacc_ctx.c  muacc_tlv.c  muacc_util.c strbuf.c dlog.c socketset.c)
SET_TARGET_PROPERTIES(muacc PROPERTIES POSITION_INDEPENDENT_CODE 1)

INSTALL(FILES intents.h muacc_util.h muacc.h strbuf.h dlog.h socketset.h
    DESTINATION include/muacc
)
