INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIR})

ADD_LIBRARY(policy_sample MODULE policy_sample.c policy_util.c)
#TARGET_LINK_LIBRARIES(policy_sample policy_util)

ADD_LIBRARY(policy_rr_naive MODULE policy_rr_naive.c policy_util.c)
#TARGET_LINK_LIBRARIES(policy_rr_naive policy_util)

ADD_LIBRARY(policy_filesize MODULE policy_filesize.c policy_util.c)
#TARGET_LINK_LIBRARIES(policy_filesize policy_util)

ADD_LIBRARY(policy_intents MODULE policy_intents.c policy_util.c)
#TARGET_LINK_LIBRARIES(policy_intents policy_util)

