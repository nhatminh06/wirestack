cmake_minimum_required(VERSION 3.20)
project(wirestack CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

option(WIRESTACK_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

add_library(wirestack_core STATIC
    src/mac_address.cpp
    src/ipv4_address.cpp
    src/ethernet.cpp
    src/tap_device.cpp
    src/arp.cpp
    src/arp_cache.cpp
    src/checksum.cpp
    src/ipv4.cpp
    src/icmp.cpp
    src/udp.cpp
    src/udp_endpoint.cpp
    src/tcp.cpp
    src/tcp_connection.cpp
    src/http.cpp
    src/http_client.cpp
)

target_include_directories(wirestack_core PUBLIC include)

target_compile_options(wirestack_core PUBLIC
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

if(WIRESTACK_ENABLE_SANITIZERS)
    target_compile_options(wirestack_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(wirestack_core PUBLIC -fsanitize=address,undefined)
endif()

add_executable(wirestack src/main.cpp)
target_link_libraries(wirestack PRIVATE wirestack_core)

add_executable(tap_send tools/tap_send.cpp)
target_link_libraries(tap_send PRIVATE wirestack_core)
set_target_properties(tap_send PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)

enable_testing()
add_subdirectory(tests)
