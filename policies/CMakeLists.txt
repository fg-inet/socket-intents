INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIR})

ADD_LIBRARY(policy_sample MODULE policy_sample.c policy_util.c)
SET_TARGET_PROPERTIES(policy_sample PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_sample ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_rr_naive MODULE policy_rr_naive.c policy_util.c)
SET_TARGET_PROPERTIES(policy_rr_naive PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_rr_naive ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_filesize MODULE policy_filesize.c policy_util.c)
SET_TARGET_PROPERTIES(policy_filesize PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_filesize ${GLIB2_LIBRARIES})

ADD_LIBRARY(policy_intents MODULE policy_intents.c policy_util.c)
SET_TARGET_PROPERTIES(policy_intents PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(policy_intents ${GLIB2_LIBRARIES})

