cmake_minimum_required(VERSION 3.10)
project(YamlDemo)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找 yaml-cpp 库
find_package(yaml-cpp REQUIRED)

# 添加可执行文件（建议使用项目名作为目标名）
add_executable(YamlDemo tc_pro_get.cpp)

# 链接 yaml-cpp 库
target_link_libraries(YamlDemo PRIVATE yaml-cpp)

