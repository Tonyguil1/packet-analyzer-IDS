cmake_minimum_required(VERSION 3.16)

project(PacketIDS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_path(PCAP_INCLUDE_DIR
    NAMES pcap/pcap.h
    REQUIRED
)

find_library(PCAP_LIBRARY
    NAMES pcap
    REQUIRED
)

add_executable(packet-ids
    src/main.cpp
    src/PacketCapture.cpp
    src/PacketParser.cpp
)

target_include_directories(packet-ids PRIVATE
    include
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(packet-ids PRIVATE
    ${PCAP_LIBRARY}
)

target_compile_options(packet-ids PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)
