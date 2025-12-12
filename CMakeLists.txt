cmake_minimum_required(VERSION 3.20)

project(airpods
    VERSION 0.1.0
    DESCRIPTION "AirPods daemon for Linux"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Common library (protocol parsing, types - no platform dependencies)
add_subdirectory(common)

# Linux daemon
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(linux)
endif()
