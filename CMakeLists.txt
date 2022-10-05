cmake_minimum_required(VERSION 3.16)

project(pplp)

# check if support c++17
# message("List of compile features: ${CMAKE_CXX_COMPILE_FEATURES}")
set(CMAKE_BUILD_TYPE Release) # lib is release version
set(CMAKE_CXX_STANDARD 17)

# check results and add flag
# if(COMPILER_SUPPORTS_CXX17)#
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
# message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has C++17 support!!")
# elseif(COMPILER_SUPPORTS_CXX11)#
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support. Please use a different C++ compiler.")
# else()
# message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++14 support. Please use a different C++ compiler.")
# endif()
find_package(SEAL 4.0 REQUIRED)

# non-interactive demo
add_executable(pplp src/main.cc src/demo.cc)

add_executable(client src/client.cc)
add_executable(server src/server.cc)

target_include_directories(client PRIVATE ./include)
target_link_libraries(client PRIVATE SEAL::seal)
target_include_directories(server PRIVATE ./include)
target_link_libraries(server PRIVATE SEAL::seal)
target_include_directories(pplp PRIVATE ./include)
target_link_libraries(pplp PRIVATE SEAL::seal)
