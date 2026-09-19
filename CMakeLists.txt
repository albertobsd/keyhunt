# ---------------------------------------------------------------------------
# keyhunt - cross-platform build (Linux/GCC/Clang and Windows/MSVC 2017+)
#
#   Linux / macOS:
#       cmake -B build -DCMAKE_BUILD_TYPE=Release
#       cmake --build build -j
#
#   Windows (MSVC 2017, from a "x64 Native Tools" prompt or via -A x64):
#       cmake -B build -G "Visual Studio 15 2017" -A x64
#       cmake --build build --config Release
#
# The result is the "keyhunt" executable in the build directory.
# ---------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.10)

project(keyhunt
    VERSION 1.0
    DESCRIPTION "KeyHunt - Bitcoin key search tool"
    LANGUAGES C CXX)

# This project uses 64-bit integer intrinsics (_addcarry_u64, _umul128, ...)
# and 64-bit pointers throughout; it cannot be built as a 32-bit target.
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
        "keyhunt requires a 64-bit build. On MSVC pass -A x64; on GCC/Clang "
        "use a 64-bit toolchain (do not pass -m32).")
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

# Optional: tune the binary for the machine doing the build (GCC/Clang only).
# Off by default so the produced binary stays portable; enable with
# -DKEYHUNT_NATIVE=ON for maximum performance on that same CPU.
option(KEYHUNT_NATIVE "Optimize for the build host CPU (-march=native)" OFF)

set(KEYHUNT_SOURCES
    keyhunt.cpp
    oldbloom/oldbloom.cpp
    bloom/bloom.cpp
    base58/base58.c
    rmd160/rmd160.c
    sha3/sha3.c
    sha3/keccak.c
    xxhash/xxhash.c
    util.c
    secp256k1/Random.cpp
    hash/ripemd160.cpp
    hash/sha256.cpp
    hash/ripemd160_sse.cpp
    hash/sha256_sse.cpp
    secp256k1/Int.cpp
    secp256k1/Point.cpp
    secp256k1/SECP256K1.cpp
    secp256k1/IntMod.cpp
    secp256k1/IntGroup.cpp
)

# getopt() is part of the C library on POSIX; on native Windows we ship our own.
if(WIN32)
    list(APPEND KEYHUNT_SOURCES getopt.c)
endif()

add_executable(keyhunt ${KEYHUNT_SOURCES})
target_include_directories(keyhunt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# These carry a .c extension but are C++ translation units (they include
# <cstring> and are linked against C++ callers). Compile them as C++ so both
# GCC/Clang and MSVC treat them the same way the original Makefile did (g++).
set_source_files_properties(util.c sha3/sha3.c sha3/keccak.c
    PROPERTIES LANGUAGE CXX)

if(MSVC)
    # WIN64 is what the sources gate their Windows paths on; MSVC only
    # predefines _WIN64. Silence the CRT "unsafe function" deprecation noise.
    target_compile_definitions(keyhunt PRIVATE
        WIN64
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_DEPRECATE
        NOMINMAX)
    # /wd4244 /wd4267: silence the benign "possible loss of data" narrowing
    # conversions that are pervasive in the upstream code.
    target_compile_options(keyhunt PRIVATE /O2 /EHsc /wd4244 /wd4267)
else()
    target_compile_options(keyhunt PRIVATE
        -O3 -mssse3 -Wall -Wextra -Wno-unused-parameter
        $<$<COMPILE_LANGUAGE:CXX>:-Wno-deprecated-copy>)
    if(KEYHUNT_NATIVE)
        target_compile_options(keyhunt PRIVATE -march=native -mtune=native)
    endif()
    find_package(Threads REQUIRED)
    target_link_libraries(keyhunt PRIVATE Threads::Threads m)
endif()
