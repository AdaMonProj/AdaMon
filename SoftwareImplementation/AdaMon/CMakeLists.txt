cmake_minimum_required(VERSION 3.20)

project(AdaMon)

add_library(
    AdaMon
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/AdaMon.cpp
)

target_include_directories(
    AdaMon
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    AdaMon
    PUBLIC
    hashfunc
    utility
)

# test executable
add_executable(test_AdaMon ${CMAKE_CURRENT_SOURCE_DIR}/src/test_AdaMon.cpp)

target_link_libraries(
    test_AdaMon
    PRIVATE
    AdaMon
    mylibpcap
)