cmake_minimum_required(VERSION 3.10)
project(YamlDemo)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找 yaml-cpp 库
find_package(yaml-cpp REQUIRED)

# 查找 libbpf、libelf、zlib（系统库）
find_library(LIBBPF_LIB bpf REQUIRED)
find_library(ELF_LIB elf REQUIRED)
find_library(ZLIB_LIB z REQUIRED)

# 查找 libbpf 头文件路径（可选，如果你手动安装了 libbpf）
find_path(LIBBPF_INCLUDE_DIR bpf/libbpf.h)

# 添加可执行文件
add_executable(YamlDemo tc_pro_get.cpp)

# 添加头文件路径（如果找到了 libbpf 头文件）
if (LIBBPF_INCLUDE_DIR)
    target_include_directories(YamlDemo PRIVATE ${LIBBPF_INCLUDE_DIR})
endif()

# 链接所有依赖库
target_link_libraries(YamlDemo PRIVATE yaml-cpp ${LIBBPF_LIB} ${ELF_LIB} ${ZLIB_LIB})

