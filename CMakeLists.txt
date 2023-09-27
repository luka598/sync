cmake_minimum_required(VERSION 3.24)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Do not build in-source. Please remove CMakeCache.txt and the CMakeFiles/ directory. Then build out-of-source")
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

project(sync VERSION 1.0.0.0 LANGUAGES CXX)
message(${PROJECT_NAME} ${${PROJECT_NAME}_VERSION})

find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git
                         GIT_TAG 0817715923c9705e68994eb52ef9df3f6845beba) # The commit hash for 1.10.x. Replace with the latest from: https://github.com/libcpr/cpr/releases
FetchContent_MakeAvailable(cpr)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)

configure_file(src/config.hpp.in config.hpp)

add_executable(${PROJECT_NAME}
	src/main.cpp
  src/file.cpp
  src/crypto.cpp
  src/bytes.cpp
  src/dropbox.cpp
)
target_link_libraries(${PROJECT_NAME}
  PRIVATE
  OpenSSL::Crypto
  cpr::cpr
  nlohmann_json::nlohmann_json
)
