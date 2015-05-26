INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIR})

ADD_LIBRARY(policy_sample MODULE policy_sample.c policy_util.c)
SET_TARGET_PROPERTIES(policy_sample PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_sample mam ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_rr_naive MODULE policy_rr_naive.c policy_util.c)
SET_TARGET_PROPERTIES(policy_rr_naive PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_rr_naive mam ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_filesize MODULE policy_filesize.c policy_util.c)
SET_TARGET_PROPERTIES(policy_filesize PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_filesize mam ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_intents MODULE policy_intents.c policy_util.c)
SET_TARGET_PROPERTIES(policy_intents PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_intents mam ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_rr_pipelining MODULE policy_rr_pipelining.c policy_util.c)
SET_TARGET_PROPERTIES(policy_rr_pipelining PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_rr_pipelining mam ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_gpac_test MODULE policy_gpac_test policy_util.c)
SET_TARGET_PROPERTIES(policy_gpac_test PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_gpac_test mam ${GLIB2_LIBRARIES})

INSTALL(TARGETS policy_sample policy_rr_naive policy_filesize policy_intents policy_rr_pipelining policy_gpac_test
	DESTINATION "${CMAKE_INSTALL_PREFIX}/${POLICY_PATH}"
)
