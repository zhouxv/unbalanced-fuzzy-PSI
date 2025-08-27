# 配置文件，将config.h.in处理为config.h
configure_file(config.h.in "config.h")

# 设置源文件列表
set(SRCS
    "SimpleIndex.cpp"
    "fileBased.cpp"
)

# 创建静态库volePSI
add_library(volePSI STATIC ${SRCS})

# 使包含volePSI的项目使用此作为包含目录
target_include_directories(volePSI PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
    $<INSTALL_INTERFACE:include>)
target_include_directories(volePSI PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<INSTALL_INTERFACE:include>)

# 链接依赖库
target_link_libraries(volePSI PUBLIC oc::libOTe sparsehash libdivide)

# 针对苹果系统的编译选项
if(APPLE)
    target_compile_options(volePSI PRIVATE
        "-std=c++${VOLE_PSI_STD_VER}"
    )

    # 禁用某些警告
    target_compile_options(volePSI PRIVATE
        "-Wno-pessimizing-move"
        "-Wno-delete-non-abstract-non-virtual-dtor"
    )

# 针对MSVC编译器的设置
elseif(MSVC)
    set_target_properties(volePSI
        PROPERTIES
        CXX_STANDARD ${VOLE_PSI_STD_VER}
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
    )

    # 如果启用ASAN，发出警告并添加ASAN编译和链接选项
    if(VOLE_PSI_ENABLE_ASAN)
        message(WARNING "volepsi has ASAN enabled")
        target_compile_options(volePSI PUBLIC "/fsanitize=address")
        target_link_options(volePSI PUBLIC "/fsanitize=address")
    endif()
else()
    # 针对其他系统的编译选项
    target_compile_options(volePSI PUBLIC
        "-std=c++${VOLE_PSI_STD_VER}"
    )

    # 如果启用ASAN，发出警告并添加ASAN编译和链接选项
    if(VOLE_PSI_ENABLE_ASAN)
        message(WARNING "volepsi has ASAN enabled")
        target_compile_options(volePSI PUBLIC "-fsanitize=address") # "-ftime-report")
        target_link_options(volePSI PUBLIC "-fsanitize=address")
    endif()
endif()

# 针对MSVC编译器，添加编译定义
if(MSVC)
    target_compile_definitions(volePSI PUBLIC "_ENABLE_EXTENDED_ALIGNED_STORAGE")
else()
    # 如果启用SSE，添加相应的编译选项
    if(VOLE_PSI_ENABLE_SSE)
        target_compile_options(volePSI PUBLIC -mavx)
    endif()

    # 如果启用PIC，添加相应的编译选项
    if(VOLE_PSI_ENABLE_PIC)
        target_compile_options(volePSI PUBLIC "-fPIC")
    endif()
endif()

# 设置目标的编译特性
# target_compile_features(volePSI PUBLIC cxx_std_17)
message($<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..)
