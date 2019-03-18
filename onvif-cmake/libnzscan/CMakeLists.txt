if (CMAKE_BUILD_TYPE)
else()
	set(CMAKE_BUILD_TYPE Release)
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
	set(libname nzscand)
elseif (CMAKE_BUILD_TYPE MATCHES Release)
	set(libname nzscan)
endif()

message(STATUS "libname:" ${libname})

#c++11
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(link_libs ssl crypto)
if (WIN32)
	set(link_libs ssleay32 libeay32)
endif()

message(STATUS "link_libs:" ${link_libs})

aux_source_directory(./src src_list)
#头文件路径
include_directories(./headers /usr/local/Cellar/openssl/1.0.2n/include/)
#链接库路径
link_directories(/usr/local/Cellar/openssl/1.0.2n/lib /usr/lib/x86_64-linux-gnu)
#需要连接的动态库
link_libraries(${link_libs})
#添加一些编译参数
set(complie_flags "-DWITH_OPENSSL -DNDTCP_FASTOPEN")
if (WIN32)
	set(complie_flags "${complie_flags} -D_CRT_SECURE_NO_WARNINGS")
endif()
add_definitions(${complie_flags})

message(STATUS "complie_flags：" ${complie_flags})

add_library(${libname} SHARED ${src_list})
