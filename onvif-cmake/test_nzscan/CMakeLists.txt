aux_source_directory(./src src_list )

message(STATUS "***************" ${src_list})

#c++11
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if (CMAKE_BUILD_TYPE)
else()
	set(CMAKE_BUILD_TYPE Release)
endif()

#链接库路径
link_directories("./" "/usr/local/Cellar/openssl/1.0.2n/lib")

if (CMAKE_BUILD_TYPE MATCHES Debug)
	set(linklib nzscand)
	set(exename scand)
elseif (CMAKE_BUILD_TYPE MATCHES Release)
	set(linklib nzscan)
	set(exename scan)
endif()

message(STATUS "libname:" ${linklib})
message(STATUS "exename:" ${exename})

#链接库名
link_libraries(${linklib})

add_executable(${exename} ${src_list})
