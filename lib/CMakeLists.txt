set(CMAKE_THREAD_PREFER_PTHREAD)
include(FindThreads)

add_library(watchman SHARED
	tesla_class.c
	tesla_class_global.c
	tesla_class_perthread.c
	tesla_debug.c
	tesla_dtrace.c
	tesla_notification.c
	tesla_store.c
	tesla_update.c
	tesla_util.c
)

target_link_libraries(watchman ${CMAKE_THREAD_LIBS_INIT})


install(TARGETS watchman DESTINATION lib)
