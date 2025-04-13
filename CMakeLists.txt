# CMakeList.txt: http-server 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

# 如果支持，请为 MSVC 编译器启用热重载。
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("http-server")

# 将源代码添加到此项目的可执行文件。
file(GLOB RBS_LIB_HEADERS "rbslib/*.h" "rbslib/Windows/*.h" "rbslib/Linux/*.h")
file(GLOB RBS_LIB_SRC "rbslib/*.cpp" "rbslib/Windows/*.cpp" "rbslib/Linux/*.cpp")
file(GLOB JSON_LIB_SRC "json/*.cpp")
file(GLOB JSON_LIB_HEADERS "json/*.h")
file(GLOB LOG_LIB_SRC "liblog/*.cpp")
file(GLOB LOG_LIB_HEADERS "liblog/*.h")
add_executable (http-server "http-server.cpp" "http-server.h" ${RBS_LIB_SRC} ${RBS_LIB_HEADERS} ${JSON_LIB_HEADERS} ${JSON_LIB_SRC} ${LOG_LIB_HEADERS} ${LOG_LIB_SRC})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET http-server PROPERTY CXX_STANDARD 20)
endif()

# TODO: 如有需要，请添加测试并安装目标。
