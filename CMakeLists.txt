cmake_minimum_required(VERSION 3.20)
project(sshook_asi C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MinHook (se descarga al configurar). Se compilan sus fuentes directamente (x86 => hde32).
include(FetchContent)
FetchContent_Declare(minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        v1.3.3
    SOURCE_SUBDIR  _no_cmake_here)   # evita add_subdirectory del CMakeLists de MinHook
FetchContent_MakeAvailable(minhook)

add_library(minhook_static STATIC
    ${minhook_SOURCE_DIR}/src/buffer.c
    ${minhook_SOURCE_DIR}/src/hook.c
    ${minhook_SOURCE_DIR}/src/trampoline.c
    ${minhook_SOURCE_DIR}/src/hde/hde32.c)
target_include_directories(minhook_static PUBLIC ${minhook_SOURCE_DIR}/include)

function(add_asi name)
    add_library(${name} SHARED ${ARGN})
    set_target_properties(${name} PROPERTIES PREFIX "" SUFFIX ".asi")
    target_link_libraries(${name} PRIVATE minhook_static user32 kernel32)
    target_link_options(${name} PRIVATE -static -static-libgcc -static-libstdc++)
endfunction()

add_asi(sshook_borderless  borderless/borderless.cpp)
add_asi(sshook_crashfixes  crashfixes/crashfixes.cpp)
add_asi(sshook_matfix      matfix/matfix.cpp)
