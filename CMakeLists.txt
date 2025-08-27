cmake_minimum_required(VERSION 3.22)
project(okvr-fpsi)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/out/install")


include_directories(frontend)
include_directories(ufpsi)
include_directories(components)
include_directories(${CMAKE_SOURCE_DIR}/out/install/include)

file(GLOB_RECURSE SRCS
    frontend/*.cpp
    ufpsi/*.cpp
    components/*.cpp
)

add_executable(main ${SRCS})

target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
set(CMAKE_BUILD_TYPE Release)

# # ############################################
# # Link  IPCL                                 #
# # ############################################
find_package(IPCL 2.0.0
    HINTS
    REQUIRED)
target_link_libraries(main IPCL::ipcl)

# # ############################################
# # Link  libOTe                               #
# # ############################################
find_package(libOTe REQUIRED)
target_link_libraries(main oc::libOTe)

# # ############################################
# # Link  Myblake3                             #
# # ############################################
target_link_libraries(main ${CMAKE_SOURCE_DIR}/out/install/lib/libblake3.a)


# # ############################################
# # Link  spdlog                               #
# # ############################################
if(NOT TARGET spdlog)
    # Stand-alone build
    find_package(spdlog REQUIRED)
endif()

target_link_libraries(main spdlog::spdlog $<$<BOOL:${MINGW}>:ws2_32>)