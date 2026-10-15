
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

include(FetchContent)

# Set the compilation flags required for debug and release builds.
set(can_use_assembler TRUE)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g3 -fno-stack-protector -Wall -Wno-error=unused-parameter -Wextra -Wshadow -Wformat -Wformat-security")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -Werror=format-security -Werror=implicit-function-declaration -fstack-protector -Wall -Wextra -Wshadow -Werror=format-security -Wno-error=unused-but-set-variable
    Wno-error=comment -Wl,--gc-sections")

# Declares the project name. The project name can be accessed via ${ PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
project("fuadxshell")

set(LLVM_STRIP "C:/Android/ndk/29.0.13599879/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe")

# Find libraries in project's build environment.
find_library(log-lib log)
find_library(android-lib android)
find_library(z-lib z)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
#
# In this top level CMakeLists.txt, ${CMAKE_PROJECT_NAME} is used to define
# the target library name; in the sub-module's CMakeLists.txt, ${PROJECT_NAME}
# is preferred for the same purpose.
#
# In order to load a library into your app from Java/Kotlin, you must call
# System.loadLibrary() and pass the name of the library defined here;
# for GameActivity/NativeActivity derived applications, the same library name must be
# used in the AndroidManifest.xml file.

FetchContent_Declare(
    minizip-ng
    GIT_REPOSITORY https://github.com/zlib-ng/minizip-ng.git
    GIT_TAG        4.0.10
)
set(MZ_OPENSSL OFF CACHE BOOL "" FORCE)
set(MZ_BZIP2 OFF CACHE BOOL "" FORCE)
set(MZ_LZMA OFF CACHE BOOL "" FORCE)
set(MZ_ZIP_NO_CENTRAL_HEADER_FILENAMES OFF CACHE BOOL
        "Keep filenames available in mz_zip_file" FORCE)
FetchContent_MakeAvailable(minizip-ng)

FetchContent_Declare(
        json_c
        GIT_REPOSITORY https://github.com/json-c/json-c.git
        GIT_TAG        json-c-0.18-20240915    # o la versión que necesites
)
set(BUILD_SHARED_LIBS     OFF CACHE BOOL "" FORCE)
set(JSON_C_BUILD_SHARED   OFF CACHE BOOL "" FORCE)
set(JSON_C_WITH_UTILS     OFF CACHE BOOL "" FORCE)  # si no necesitas los binarios de utilidades
FetchContent_MakeAvailable(json_c)

add_library(json-c::json-c ALIAS json-c)

# OPENSSL #
set(OPENSSL_VERSION 3.5.1)
set(OPENSSL_BASENAME "openssl_${OPENSSL_VERSION}")
set(OPENSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/main/c/openssl/${OPENSSL_BASENAME}_${ANDROID_ABI}")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT}/include")
set(OPENSSL_LIB_DIR "${OPENSSL_ROOT}/lib")

add_library(openssl_crypto STATIC IMPORTED)
set_target_properties(openssl_crypto PROPERTIES IMPORTED_LOCATION
    "${OPENSSL_LIB_DIR}/libcrypto.a")

add_library(openssl_ssl STATIC IMPORTED)
set_target_properties(openssl_ssl PROPERTIES IMPORTED_LOCATION
    "${OPENSSL_LIB_DIR}/libssl.a")

add_library(reflection STATIC
    main/c/reflection/reflection.c)

add_library(chacha STATIC
    main/c/fuadxshell_crypto/chacha20poly1305/chachapoly.c
    main/c/fuadxshell_crypto/chacha20poly1305/poly1305.c
    main/c/fuadxshell_crypto/chacha20poly1305/chacha.c)

add_library(rc4 STATIC
    main/c/fuadxshell_crypto/rc4/rc4.c)

add_library(twofish STATIC
    main/c/fuadxshell_crypto/twofish/twofish.c)

add_library(hook STATIC
    main/c/hook/hook.c)

add_library(emulator STATIC
    main/c/emulator/emulator.c)

add_library(fuadxshell_debug STATIC
    main/c/debug/debug.c)

add_library(root_lib STATIC
        main/c/root/root.c)

#add_library(argon2 STATIC
#    main/c/crypto/argon2/argon2.c
#    main/c/crypto/argon2/blake2.c
#    main/c/crypto/argon2/core.c
#    main/c/crypto/argon2/encoding.c
#    main/c/crypto/argon2/thread.c
#    main/c/crypto/argon2/ref.c
#)

#add_library(twofish STATIC
#    main/c/crypto/twofish/twofish.c)

#add_library(chachapoly1305 STATIC
#    main/c/crypto/chacha20poly1305/chacha.c
#    main/c/crypto/chacha20poly1305/poly1305.c
#    main/c/crypto/chacha20poly1305/chachapoly.c)

add_library(fuadxshell_utils STATIC
    main/c/fuadxshell/fuadxshell_utils.c)

add_library(logger STATIC
        main/c/logger/logger.c)

add_library(pinning STATIC
    main/c/pinning/pinning.c
)

add_library(whitebox STATIC
    main/c/whitebox/aes_wb.c
    main/c/whitebox/aes_internal.c)

add_library(${CMAKE_PROJECT_NAME} SHARED
        # List C/C++ source files with relative paths to this CMakeLists.txt.
        main/c/unpack.h
        main/c/unpack.c)

# Specifies a path to native header files. You can use this
# command multiple times if you have multiple directories with
# header files. The path is relative to the CMakeLists.txt file
# that specifies it. The path must be specified in the form
# <INTERFACE|PUBLIC|PRIVATE> <directory> or
# <INTERFACE|PUBLIC|PRIVATE> <directory1> <directory2> ... .
# The INTERFACE keyword specifies that the include directory is only
# needed for the consumers of the library.
target_include_directories(fuadxshell_utils
        PRIVATE
        $<TARGET_PROPERTY:MINIZIP::minizip,SOURCE_DIR>  # raíz del repo
)
# 5) Indícale dónde están los headers de json-c
target_include_directories(logger
        PUBLIC
        ${json-c_SOURCE_DIR}/include
        $<TARGET_PROPERTY:MINIZIP::minizip,SOURCE_DIR>
)
target_include_directories(fuadxshell_debug
        PUBLIC
        ${json-c_SOURCE_DIR}/include
)
target_include_directories(whitebox
        PUBLIC
        $<TARGET_PROPERTY:MINIZIP::minizip,SOURCE_DIR>
)
target_include_directories(twofish
        PUBLIC
        $<TARGET_PROPERTY:MINIZIP::minizip,SOURCE_DIR>
)
target_include_directories(reflection PUBLIC main/c/reflection)
target_include_directories(reflection PUBLIC main/c/minizip)
target_include_directories(reflection PUBLIC main/c/fuadxshell)
target_include_directories(reflection PUBLIC main/c)
#target_include_directories(crypto PUBLIC main/c/crypto)
#target_include_directories(crypto PUBLIC main/c/fuadxshell)
target_include_directories(hook PUBLIC main/c/hook)
target_include_directories(hook PUBLIC main/c/fuadxshell)
target_include_directories(emulator PUBLIC main/c/emulator)
target_include_directories(emulator PUBLIC main/c/fuadxshell)
target_include_directories(fuadxshell_debug PUBLIC main/c/debug)
target_include_directories(fuadxshell_debug PUBLIC main/c/fuadxshell)
#target_include_directories(argon2 PUBLIC main/c/crypto/argon2)
#target_include_directories(twofish PUBLIC main/c/fuadxshell)
#target_include_directories(twofish PUBLIC main/c/crypto/twofish)
#target_include_directories(chachapoly1305 PUBLIC main/c/fuadxshell)
#target_include_directories(chachapoly1305 PUBLIC main/c/crypto/chacha20poly1305)
target_include_directories(fuadxshell_utils PUBLIC main/c/fuadxshell)
target_include_directories(fuadxshell_utils PUBLIC ${OPENSSL_INCLUDE_DIR})
target_include_directories(logger PUBLIC main/c/fuadxshell)
target_include_directories(logger PUBLIC main/c/logger)
target_include_directories(logger PUBLIC main/c/emulator)
target_include_directories(pinning PUBLIC main/c/pinning)
target_include_directories(pinning PUBLIC main/c/fuadxshell)
target_include_directories(pinning PUBLIC main/c/logger)
target_include_directories(pinning PUBLIC ${OPENSSL_INCLUDE_DIR})
target_include_directories(whitebox PUBLIC main/c/whitebox)
target_include_directories(whitebox PUBLIC main/c/fuadxshell)
target_include_directories(fuadxshell_utils PUBLIC main/c/whitebox)
target_include_directories(chacha PUBLIC main/c/fuadxshell_crypto/chacha20poly1305)
target_include_directories(chacha PUBLIC main/c/fuadxshell)
target_include_directories(rc4 PUBLIC main/c/fuadxshell_crypto/rc4)
target_include_directories(rc4 PUBLIC main/c/fuadxshell)
target_include_directories(twofish PUBLIC main/c/fuadxshell_crypto/twofish)
target_include_directories(twofish PUBLIC main/c/fuadxshell)
target_include_directories(twofish PUBLIC ${OPENSSL_INCLUDE_DIR})
target_include_directories(root_lib PUBLIC main/c/root)
target_include_directories(root_lib PUBLIC main/c/fuadxshell)

target_compile_options(${CMAKE_PROJECT_NAME}
    PRIVATE
    # List compilation options for the target library
    #-fsanitize=address -fsanitize=leak
    -fno-omit-frame-pointer -fvisibility=hidden -fvisibility-inlines-hidden -fPIC -fno-c++-static-destructors -fno-unwind-tables)

# Specifies libraries CMake should link to your target library. You
# can link libraries from various origins, such as libraries defined in this
# build script, prebuilt third-party libraries, or Android system libraries.
target_link_libraries(logger
        PUBLIC
        fuadxshell_utils
        json-c::json-c
)

target_link_libraries(fuadxshell_debug
    PUBLIC
    logger)

target_link_libraries(emulator
    PUBLIC
    logger)

target_link_libraries(pinning
    PUBLIC
    openssl_crypto
    openssl_ssl
    logger)

target_link_libraries(whitebox
    PUBLIC
    fuadxshell_utils)

target_link_libraries(${CMAKE_PROJECT_NAME}
    PRIVATE
    # List libraries link to the target library
    #-fsanitize=address
    #-fsanitize=leak
    #crypto
    reflection
    MINIZIP::minizip
    #minizip
    android
    hook
    emulator
    fuadxshell_debug
    #argon2
    #twofish
    #chachapoly1305
    fuadxshell_utils
    logger
    pinning
    openssl_crypto
    openssl_ssl
    whitebox
    chacha
    log
    rc4
    twofish
    root_lib
    android)

if(STRIP_DEBUG_SYMBOLS)
    message(STATUS "Stripping symbols from the library in release build")
    add_custom_command(TARGET ${CMAKE_PROJECT_NAME}
    POST_BUILD
    COMMAND ${LLVM_STRIP} -R .comment -g --strip-unneeded $<TARGET_FILE:${CMAKE_PROJECT_NAME}>
    COMMENT "Stripping ${CMAKE_PROJECT_NAME} with llvm-strip")
endif()