cmake_minimum_required(VERSION 2.6)
project(WATCHMAN)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")

#
# C/C++ build options:
#
include_directories(include)

# Always build position-independent code.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# We don't always use C++, but when we do, we prefer C++11.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# Enable lots of warnings (as used in the FreeBSD "buildworld" step).
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes -Wpointer-arith")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wreturn-type -Wcast-qual")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings -Wswitch -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-parameter -Wcast-align")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wchar-subscripts -Winline")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wnested-externs -Wredundant-decls")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wold-style-definition")


#
# Use CCache if available:
#
find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif ()


add_subdirectory(lib)
add_subdirectory(test)

# A top-level 'check' target to drive all tests.
add_custom_target(check DEPENDS libwatchman-test)
