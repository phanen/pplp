cmake_minimum_required(VERSION 3.22)

project(pplp)

find_package(SEAL 4.0 REQUIRED)

add_executable(pplp src/main.cc src/demo.cc)

target_include_directories(pplp PRIVATE ./include)
target_link_libraries(pplp PRIVATE SEAL::seal)
