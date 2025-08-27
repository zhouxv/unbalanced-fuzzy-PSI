# ############################################
# Build OKVS                  #
# ############################################

file(GLOB_RECURSE SRCS *.cpp)

add_library(OurImp ${SRCS})

set(CMAKE_CXX_STANDARD 20)

target_link_libraries(OurImp PUBLIC volePSI batchPIR)

if(MSVC)
    target_compile_options(OurImp PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${VOLE_PSI_STD_VER}>)

# target_compile_options(libOTe PRIVATE -openmp:experimental)
else()
    target_compile_options(OurImp PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${VOLE_PSI_STD_VER}>)
endif()
