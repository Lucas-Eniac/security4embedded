cmake_minimum_required(VERSION 3.20)

project(SecurityModule VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SECURITY_MODULE_BUILD_EXAMPLES "Build validation example" ON)

find_package(OpenSSL REQUIRED)

add_library(security_module SHARED
    src/core/provider_factory.cpp
    src/module.cpp
    src/providers/openssl/openssl_provider.cpp
    src/providers/openssl/openssl_factory.cpp
)

target_include_directories(security_module
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(security_module
    PRIVATE
        OpenSSL::Crypto
)

target_compile_definitions(security_module PRIVATE SECURITY_MODULE_BUILD)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(security_module PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(SECURITY_MODULE_BUILD_EXAMPLES)
    add_executable(security_validation examples/validation_demo.cpp)
    target_link_libraries(security_validation PRIVATE security_module)

    enable_testing()
    add_test(NAME security_validation COMMAND security_validation)
endif()
