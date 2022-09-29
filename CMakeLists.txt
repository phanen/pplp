cmake_minimum_required(VERSION 3.22)

project(pplp)
message("List of compile features: ${CMAKE_CXX_COMPILE_FEATURES}")

# check results and add flag
if(COMPILER_SUPPORTS_CXX17)#
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has C++17 support!!")
elseif(COMPILER_SUPPORTS_CXX11)#
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support. Please use a different C++ compiler.")
else()
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++14 support. Please use a different C++ compiler.")
endif()
# set(CMAKE_CXX_STANDARD 17)

find_package(SEAL 4.0 REQUIRED)

add_executable(pplp src/main.cc src/demo.cc)

target_include_directories(pplp PRIVATE ./include)
target_link_libraries(pplp PRIVATE SEAL::seal)
