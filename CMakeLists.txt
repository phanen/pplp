cmake_minimum_required(VERSION 3.16)

project(pplp)

# check if support c++17
# message("List of compile features: ${CMAKE_CXX_COMPILE_FEATURES}")
set(CMAKE_BUILD_TYPE Release) # lib is release version
set(CMAKE_CXX_STANDARD 17)


# CFLAGS=$(pkg-config --cflags libsodium)
# LDFLAGS=$(pkg-config --libs libsodium)

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

set(CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
 " ${CMAKE_MODULE_PATH}")

find_package(SEAL 4.1 REQUIRED)
# find_package(sodium REQUIRED)
# set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lsodium" CACHE STRING "Set C++ Compiler Flags" FORCE)

set(DEP
    SEAL::seal
    )



# non-interactive demo
add_executable(pplp src/demo.cc)
target_include_directories(pplp PRIVATE ./include)
target_link_libraries(pplp PRIVATE ${DEP})

add_executable(client src/client.cc)
target_include_directories(client PRIVATE ./include)
target_link_libraries(client PRIVATE ${DEP})

add_executable(server src/server.cc)
target_include_directories(server PRIVATE ./include)
target_link_libraries(server PRIVATE ${DEP})

# test
add_executable(tc src/test/test_client.cc)
target_include_directories(tc PRIVATE ./include)
target_link_libraries(tc PRIVATE ${DEP})

add_executable(ts src/test/test_server.cc)
target_include_directories(ts PRIVATE ./include)
target_link_libraries(ts PRIVATE ${DEP})


