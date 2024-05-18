cmake_minimum_required(VERSION 3.28)
project(dhe)

set(CMAKE_CXX_STANDARD 17)

include_directories("include/cryptopp")
link_directories("lib")
link_libraries("libcryptopp.a")

add_executable(dhe dhe.cpp)
