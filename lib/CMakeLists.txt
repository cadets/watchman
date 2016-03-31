set(CMAKE_THREAD_PREFER_PTHREAD)
include(FindThreads)

add_library(watchman SHARED
	watchman_class.c
	watchman_class_global.c
	watchman_class_perthread.c
	watchman_debug.c
	watchman_dtrace.c
	watchman_notification.c
	watchman_store.c
	watchman_update.c
	watchman_util.c
)

target_link_libraries(watchman ${CMAKE_THREAD_LIBS_INIT})


install(TARGETS watchman DESTINATION lib)
