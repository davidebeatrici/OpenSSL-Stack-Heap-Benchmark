cmake_minimum_required(VERSION 2.6)
project(OpenSSL-Stack-Heap-Benchmark)

add_executable(OpenSSL-Stack-Heap-Benchmark main.c openssl.h)

find_package(OpenSSL REQUIRED)

target_link_libraries(OpenSSL-Stack-Heap-Benchmark OpenSSL::Crypto)
