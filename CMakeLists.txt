cmake_minimum_required(VERSION 3.16)
project(proculus VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic)

include(CTest)

option(PROCULUS_REQUIRE_DB "Fail if libpq/libsodium are missing instead of skipping libs/db" OFF)

find_package(nlohmann_json 3.11 REQUIRED)

add_subdirectory(libs/common)
add_subdirectory(libs/netutil)
add_subdirectory(libs/db)
add_subdirectory(libs/timing)
add_subdirectory(libs/results)
add_subdirectory(libs/signatures)
add_subdirectory(libs/insight)
add_subdirectory(libs/web)

add_subdirectory(services/gateway)
add_subdirectory(services/ui)
add_subdirectory(services/planner)
add_subdirectory(services/scan-worker)
add_subdirectory(services/scheduler)
add_subdirectory(services/runner)
add_subdirectory(services/exporter)
add_subdirectory(services/differ)
add_subdirectory(services/http-prober)
add_subdirectory(services/signatures)