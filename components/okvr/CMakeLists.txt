cmake_minimum_required(VERSION 3.15)

project(volePSI VERSION 0.1.2)

find_program(CCACHE_PROGRAM ccache)

if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

set(VOLEPSI_BUILD ON)

# sets some variables
include(cmake/preamble.cmake)

# sets build option
include(cmake/buildOptions.cmake)

# find all the dependancies.
include(cmake/findDependancies.cmake)

# build vectorized Batched PIR
add_subdirectory(batchPIR)

# build volePSI
add_subdirectory(volePSI)

# build ourImp
add_subdirectory(ourImp)

# link the executable.
add_subdirectory(frontend)

# setup the install
include(cmake/install.cmake)