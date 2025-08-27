cmake_minimum_required(VERSION 3.0)

project(VectorizedBatchPIR)

# Get all source files under src
# 获取src目录下的所有源文件
file(GLOB_RECURSE SOURCES "src/*.cpp")

add_library(batchPIR STATIC ${SOURCES})

target_include_directories(batchPIR PUBLIC header src)

# Set C++ standard
# 设置C++标准
set_target_properties(batchPIR PROPERTIES CXX_STANDARD 11)

# Add seal library
# 添加seal库
find_package(SEAL 4.1 REQUIRED)
target_link_libraries(batchPIR SEAL::seal)

# Add compiler flags for optimization
# 添加优化的编译器标志
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(batchPIR PRIVATE "-O3")
endif()