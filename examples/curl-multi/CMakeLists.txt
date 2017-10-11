ADD_EXECUTABLE(multi-app multi-app.c)
TARGET_LINK_LIBRARIES(multi-app curl)

ADD_EXECUTABLE(multi-double multi-double.c)
TARGET_LINK_LIBRARIES(multi-double curl)

ADD_EXECUTABLE(multi-single multi-single.c)
TARGET_LINK_LIBRARIES(multi-single curl)

set_target_properties(multi-app multi-double multi-single PROPERTIES EXCLUDE_FROM_ALL 1 EXCLUDE_FROM_DEFAULT_BUILD 1)