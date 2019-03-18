cmake_minimum_required(VERSION 2.8)

if (WIN32)
	message(STATUS "Now is windows")
elseif (APPLE)
	message(STATUS "Now is Apple systems.")
elseif (UNIX)
	message(STATUS "Now is UNIX-like OS's.")
endif ()

#默认Release版本
if (CMAKE_BUILD_TYPE)
else ()
	set(CMAKE_BUILD_TYPE Release)
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
	message(STATUS "Debug model")
elseif (CMAKE_BUILD_TYPE MATCHES Release)
	message(STATUS "Release model")
endif()

message(STATUS "operation system is" ${CMAKE_SYSTEM_NAME})

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

project(nzscan)

if (WIN32)
else()
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/exe)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/exe)
endif()

message(ERROR "exe_path:" ${EXECUTABLE_OUTPUT_PATH})
message(ERROR "lib_path:" ${LIBRARY_OUTPUT_PATH})

#添加动态库子目录
add_subdirectory(libnzscan)

#添加测试程序子目录
add_subdirectory(test_nzscan)
