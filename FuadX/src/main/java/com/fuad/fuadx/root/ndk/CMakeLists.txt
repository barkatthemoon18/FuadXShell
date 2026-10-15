project(rootlib)
cmake_minimum_required(VERSION 3.4.1)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(can_use_assembler TRUE)
enable_language(ASM)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O3")

function(get_architecture ABI ARCH)
    if (ABI STREQUAL arm64-v8a)
        set(${ARCH} aarch64 PARENT_SCOPE)
    elseif (ABI STREQUAL x86_64)
        set(${ARCH} x86_64 PARENT_SCOPE)
    else()
        message(FATAL_ERROR "Unsupported ABI")
    endif()
endfunction()

add_definitions("-D_64_BIT")

find_library(log-lib log)

# CUSTOM_SHARED_LIBRARY
add_library(root SHARED root.h root.c)

target_compile_options(root
    PRIVATE
    -fvisibility=hidden -fvisibility-inlines-hidden -fPIC -fno-c++-static-destructors
        -fno-unwind-tables -Wl,--gc-sections)

target_link_libraries(root
        ${log-lib})