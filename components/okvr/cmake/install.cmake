#############################################
#            安装                           #
#############################################

# 复制依赖查找和前言文件
configure_file("${CMAKE_CURRENT_LIST_DIR}/findDependancies.cmake" "findDependancies.cmake" COPYONLY)
configure_file("${CMAKE_CURRENT_LIST_DIR}/preamble.cmake" "preamble.cmake" COPYONLY)

# 创建安装目标的缓存变量
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# 生成包含导出的配置文件
configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/volePSIConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/volePSI
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

# 检查主版本号是否定义
if(NOT DEFINED volePSI_VERSION_MAJOR)
    message("\n\n\n\n 警告，volePSI_VERSION_MAJOR 未定义 ${volePSI_VERSION_MAJOR}")
endif()

# 设置目标的版本属性
set_property(TARGET volePSI PROPERTY VERSION ${volePSI_VERSION})

# 生成配置文件的版本文件
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/volePSIConfigVersion.cmake"
  VERSION "${volePSI_VERSION_MAJOR}.${volePSI_VERSION_MINOR}.${volePSI_VERSION_PATCH}"
  COMPATIBILITY AnyNewerVersion
)

# 安装配置文件
install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/volePSIConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/volePSIConfigVersion.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/findDependancies.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/preamble.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/volePSI
)

# 安装库
install(
    TARGETS volePSI
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    EXPORT volePSITargets)

# 安装头文件
install(
    DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../volePSI"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/"
    FILES_MATCHING PATTERN "*.h")

# 安装配置
install(EXPORT volePSITargets
  FILE volePSITargets.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/volePSI
       NAMESPACE visa::
)

# 导出目标
export(EXPORT volePSITargets
       FILE "${CMAKE_CURRENT_BINARY_DIR}/volePSITargets.cmake"
       NAMESPACE visa::
)