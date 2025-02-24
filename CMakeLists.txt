cmake_minimum_required(VERSION 3.10)
project(memory)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")

add_executable(${PROJECT_NAME} src/main.cpp)