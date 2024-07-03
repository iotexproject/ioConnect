cmake_minimum_required(VERSION 3.21)

project (DeviceRegister)

option (COMPILE_LIB_SET "Set ioConnectCore compile to a Lib" ON)

include_directories(./core/src)
include_directories(./pal/linux/DeviceRegister)

add_executable(DeviceRegister main.c ./pal/linux/DeviceRegister/deviceregister.c) 

add_subdirectory(./core)

if (COMPILE_LIB_SET)
    target_link_libraries(DeviceRegister ioConnectCore)
else()
    target_sources(DeviceRegister PRIVATE ${ioConnectCore_SRC})
endif()

target_link_libraries(DeviceRegister microhttpd)

#add_compile_options(-fsanitize=address -fsanitize-recover=address -fno-stack-protector -fno-omit-frame-pointer)
#target_link_libraries(DeviceRegister asan)


