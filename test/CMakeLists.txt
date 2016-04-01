#
# Find the LLVM Integrated Tester:
#
set(LLVM_LIT "" CACHE PATH "Path to llvm-lit binary")
set(LLVM_LIT_NAMES "llvm-lit llvm-lit-devel llvm-lit38 llvm-lit37 llvm-lit36")

if (NOT LLVM_LIT)
  message(STATUS "Looking for LLVM Integrated Tester")
  find_program(LLVM_LIT_EXECUTABLE
    NAMES llvm-lit llvm-lit-devel llvm-lit38 llvm-lit37 llvm-lit36
    DOC "LLVM Integrated Tester"
  )

  if (LLVM_LIT_EXECUTABLE)
    set(LLVM_LIT "${LLVM_LIT_EXECUTABLE}")
  else ()
    message(FATAL_ERROR "LLVM Integrated Tester not found!\n"
      "Try re-running CMAKE with the argument -D LLVM_LIT=/path/to/llvm-lit "
      "or with PATH set to include a directory containing any of:\n"
      "${LLVM_LIT_NAMES}"
    )
  endif ()

  message(STATUS "Found LLVM lit: ${LLVM_LIT}")
endif ()


#
# Set up some variables to control the testing framework:
#
set(LIT_EXTRA "--param=extra_cxxflags=${CMAKE_CXX_FLAGS}")

set(SHOW_TEST_STATS false CACHE BOOL "Show statistics after running tests")
if (SHOW_TEST_STATS)
  message(STATUS "Will show statistics after each test run")
  set(LIT_OPTIONS "-sv")
else ()
  message(STATUS "Will run successful tests quietly")
  set(LIT_OPTIONS "-qv")
endif ()

set(EXPORT_XUNIT_XML true CACHE BOOL "Export test results as XUnit XML")
if (EXPORT_XUNIT_XML)
  message(STATUS "Will export test results XUnit XML")
  set(LIT_EXTRA "--xunit-xml-output=test-results.xml;${LIT_EXTRA}")
else ()
  message(STATUS "Will not export test results XUnit XML")
endif ()


#
# Platform-specific hacks for running tests:
#
if( ${CMAKE_SYSTEM_NAME} MATCHES FreeBSD )
	# We use execinfo for detailed failure information (e.g. backtraces).
	#
	# This is only required on FreeBSD, as both Mac OS X and Linux include
	# backtrace functions in libSystem / libc.
	find_package(ExecInfo REQUIRED)
	include_directories(${EXECINFO_INCLUDE_DIRS})

	set(LIT_EXTRA ${LIT_EXTRA}
		--param=extra_include_dirs=${EXECINFO_INCLUDE_DIRS}
		--param=extra_libs="-lthr:${EXECINFO_LIBRARY}")

else ( ${CMAKE_SYSTEM_NAME} MATCHES Linux )
	# On some Linux installations, we need to explicitly pass the
	# -resource-dir flag to Clang tools. The Clang driver handles this
	# automatically, and we need to figure out why the Clang tooling
	# framework doesn't. In the meantime, however, this workaround works.
	set(LIT_EXTRA ${LIT_EXTRA}
		--param=extra_cflags=-resource-dir:${CLANG_RESOURCE_DIR})
endif()


add_subdirectory(lib)
