cmake_minimum_required(VERSION 3.5)
if(CMAKE_TOOLCHAIN_FILE)
    message(STATUS "Toolchain: ${CMAKE_TOOLCHAIN_FILE}")
endif()

if(DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "Choose the type of build, options are: Debug, Release, RelWithDebInfo")
else()
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: Debug, Release, RelWithDebInfo")
endif()

message(STATUS "Mode: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CONFIGURATION_TYPES Debug RelWithDebInfo Release CACHE STRING INTERNAL)
set(ARCH native CACHE STRING  "CPU to build for: -march value or native")

message(STATUS "Building for target architecture: ${ARCH}")

set(LIB_MAJOR_VERSION "7")
set(LIB_MINOR_VERSION "0")
set(LIB_PATCH_VERSION "6")
set(LIB_VERSION_STRING "${LIB_MAJOR_VERSION}.${LIB_MINOR_VERSION}.${LIB_PATCH_VERSION}")

if(CMAKE_VERSION VERSION_LESS 3.0)
    project(crypto CXX)
    enable_language(CXX)
else()
    cmake_policy(SET CMP0048 NEW)
    project(crypto VERSION "${LIB_VERSION_STRING}" LANGUAGES CXX)
endif()

if(NOT MSVC)
    find_program(CCACHE_PROGRAM ccache)
    if(CCACHE_PROGRAM)
        message(STATUS "Found ccache package... Activating...")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
    endif()
endif()

option(BUILD_NODE "Build Node.js addon module" ON)
if(DEFINED ENV{BUILD_NODE})
    set(BUILD_NODE $ENV{BUILD_NODE})
endif()
if(BUILD_NODE)
    message(STATUS "Building Node.js addon module")
endif()

option(BUILD_JS "Build Javascript module")
if(DEFINED ENV{BUILD_JS})
    set(BUILD_JS $ENV{BUILD_JS})
endif()
if(BUILD_JS)
    message(STATUS "Building Javascript module")
endif()

option(BUILD_WASM "Build WASM module")
if(DEFINED ENV{BUILD_WASM})
    set(BUILD_WASM $ENV{BUILD_WASM})
endif()
if(BUILD_WASM)
    message(STATUS "Building WASM module")
endif()

option(DEBUG_PRINT "Enable debug print statements" OFF)
if (DEFINED ENV{DEBUG_PRINT})
    set(DEBUG_PRINT $ENV{DEBUG_PRINT})
endif()
if(DEBUG_PRINT)
    add_compile_definitions(DEBUG_PRINT=1)
    message(STATUS "Activating debug print statements")
endif()

## This section describes our general CMake setup options
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_INSTALL_RULES OFF FORCE)
set(CMAKE_SKIP_PACKAGE_ALL_DEPENDENCY ON FORCE)
set(CMAKE_SUPPRESS_REGENERATION ON)
set(CMAKE_POLICY_WARNING_CMP0048 OFF)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Enable c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

## We only build static binaries -- this is left here for our dependencies
set(STATIC ON CACHE BOOL FORCE "Link libraries statically? Forced to ON")
add_definitions(-DSTATICLIB)
add_definitions(-DRAPIDJSON_HAS_STDSTRING)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D_CRT_SECURE_NO_WARNINGS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std:c++17 /wd4267 /wd4804 /wd4996 /D_DLL /D_CRT_SECURE_NO_WARNINGS")

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
else()
    if("${ARCH}" STREQUAL "default")
        set(ARCH_FLAG "")
    else()
        set(ARCH_FLAG "-march=${ARCH}")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wuninitialized ${MAES_FLAG}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wuninitialized ${MAES_FLAG}")

    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -Og")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -Og")

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG -O3")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG -O3")

    if(APPLE)
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            # Need to build against libc++ instead of libstc++ on apple
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++ -I/usr/local/opt/llvm/include/c++/v1 -nodefaultlibs -lc++ -lc++abi -lm -lc -lgcc -lgcc_eh")

            # Need these flags so gcc OSX works on the cryptopp ASM - https://groups.google.com/forum/#!topic/cryptopp-users/po8yO-vYaac
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER=1")

        elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
            # Need to link against the llvm libc++ library, default is too old for std::filesystem
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -I/usr/local/opt/llvm/include/c++/v1")
        endif()
    endif()

    if(MINGW OR STATIC_LIBC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libstdc++")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()

    if(NOT APPLE)
        set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()

add_subdirectory(external)
include_directories(include)
file(GLOB MODULE_SOURCE_FILES src/module.cpp)

if(BUILD_NODE AND NOT CMAKE_JS_VERSION)
    include("scripts/cmakejs.cmake")
    setup_cmakejs()
endif()

if (CMAKE_JS_VERSION)
    message(STATUS "CMake-js: ${CMAKE_JS_VERSION}")
    message(STATUS "CMAKE_JS_INC: ${CMAKE_JS_INC}")
    message(STATUS "CMAKE_JS_SRC: ${CMAKE_JS_SRC}")
    message(STATUS "CMAKE_JS_LIB: ${CMAKE_JS_LIB}")
    add_compile_definitions(__NODE__)

    if(MSVC)
        # https://github.com/refack/node/blob/965ffc4cb9a55d26192a95485b57afe4573990b0/common.gypi#L275
        add_definitions("/wd4351 /wd4355 /wd4800 /wd4251 /wd4275 /wd4244 /wd4996")
    endif()

    add_library(crypto-module SHARED ${MODULE_SOURCE_FILES} ${CMAKE_JS_SRC})
    target_include_directories(crypto-module PRIVATE ${CMAKE_JS_INC})
    target_link_libraries(crypto-module crypto-static ${CMAKE_JS_LIB})
    set_target_properties(crypto-module PROPERTIES
        PREFIX                      ""
        SUFFIX                      ".node"
        LINKER_LANGUAGE             CXX
    )
endif()

if(BUILD_JS OR BUILD_WASM)
    add_compile_definitions(__JAVASCRIPT__)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "")
    add_executable(crypto-module ${MODULE_SOURCE_FILES})
    target_link_libraries(crypto-module crypto-static)

    # Override our release flags for emscripten compatibility
    set(CMAKE_C_FLAGS_DEBUG "")
    set(CMAKE_CXX_FLAGS_DEBUG "")
    set(CMAKE_C_FLAGS_RELEASE "-O3 --llvm-lto 3 -DNDEBUG -Wno-unused-variable -fexceptions")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 --llvm-lto 3 -DNDEBUG -Wno-unused-variable -fexceptions")

    set(JS_LINKFLAGS
            --llvm-opts 3
            --llvm-lto 3
            --closure 1
            -fexceptions
            -s SINGLE_FILE=1
            -s EXPORT_NAME="'CryptoModule'"
            -s POLYFILL_OLD_MATH_FUNCTIONS=1
            -s MODULARIZE=1
            -s ASSERTIONS=1
            -s DYNAMIC_EXECUTION=0
            --bind
    )

    string(REPLACE ";" " " JS_LINKFLAGS_STR "${JS_LINKFLAGS}")

    if(BUILD_JS)
        set(CMAKE_EXECUTABLE_SUFFIX ".js")
        set(JS_LINKFLAGS_STR "${JS_LINKFLAGS_STR} -s WASM=0 --js-opts 1")
        message(STATUS "emcc flags: ${JS_LINKFLAGS_STR}")
        set_target_properties(crypto-module PROPERTIES LINK_FLAGS "${JS_LINKFLAGS_STR}")
    endif()

    if(BUILD_WASM)
        set(CMAKE_EXECUTABLE_SUFFIX "-wasm.js")
        set(JS_LINKFLAGS_STR "${JS_LINKFLAGS_STR} -s WASM=1 -s BINARYEN_METHOD='native-wasm'")
        message(STATUS "emcc flags: ${JS_LINKFLAGS_STR}")
        set_target_properties(crypto-module PROPERTIES LINK_FLAGS "${JS_LINKFLAGS_STR} -s WASM=1 -s BINARYEN_METHOD='native-wasm'")
    endif()
endif()
