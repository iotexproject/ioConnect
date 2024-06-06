cmake_minimum_required(VERSION 3.21)

project (DIDComm_Server)

option (COMPILE_LIB_SET "Set ioConnectCore compile to a Lib" ON)

include_directories(./core/src)

add_compile_options(-g -O0)

add_executable(DIDComm_Server main.c) 

add_subdirectory(./core)

if (COMPILE_LIB_SET)
    target_link_libraries(DIDComm_Server ioConnectCore)
else()
    target_sources(DIDComm_Server PRIVATE ${ioConnectCore_SRC})
endif()

#add_compile_options(-fsanitize=address -fsanitize-recover=address -fno-stack-protector -fno-omit-frame-pointer)
#target_link_libraries(DIDComm_Server asan)


