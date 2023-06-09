cmake_minimum_required(VERSION 3.25)
project(edge)

set(CMAKE_CXX_STANDARD 20)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_library(${PROJECT_NAME}_lib ${SOURCES})

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_lib)

enable_testing()

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/release-1.12.0.zip
)
FetchContent_MakeAvailable(googletest)

file(GLOB_RECURSE TEST_FILES CONFIGURE_DEPENDS tests/*.cpp)
add_executable(${PROJECT_NAME}_test ${TEST_FILES})

target_link_libraries(${PROJECT_NAME}_test PRIVATE gtest_main ${PROJECT_NAME}_lib)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME}_test)
