cmake_minimum_required(VERSION 3.5)

if (MSVC)
    # warning level 4
    add_compile_options(/W4)
else()
    add_compile_options(-O1 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -ftrapv 
    -fstack-protector-strong -Winit-self 
    #-fPIE -Wdate-time -frandom-seed=0
    -Wdeclaration-after-statement
    -Wunused-variable -Wunused-parameter
    -Wconversion -Wsign-conversion
    -Wvla
    -Wrestrict
    -Wimplicit-fallthrough
    -Wimplicit-function-declaration
    -Wimplicit-int 
    -Wreturn-type
    -std=c99)
endif()

#test projet 
project(test_utils)
project(test_gadgets)
project(test_chenchen_gadgets)
project(test_secfpr)

project(test_final)


set(GADGETS_SOURCES src/utils.c src/gadgets.c src/chenchen_gadgets.c src/chenchen_modify.c src/secfpr.c)

include_directories(include)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEX2" CACHE STRING _FORTIFY_SOURCE FORCE)

add_library(gadgets SHARED ${GADGETS_SOURCES})

add_executable(test_utils apps/test_utils.c)
target_link_libraries(test_utils gadgets m)

add_executable(test_gadgets apps/test_gadgets.c)
target_link_libraries(test_gadgets gadgets m)

add_executable(test_chenchen_gadgets apps/test_chenchen_gadgets.c)
target_link_libraries(test_chenchen_gadgets gadgets m)

add_executable(test_secfpr apps/test_secfpr.c)
target_link_libraries(test_secfpr gadgets m)

add_executable(test_final apps/test_final.c)
target_link_libraries(test_final gadgets m)