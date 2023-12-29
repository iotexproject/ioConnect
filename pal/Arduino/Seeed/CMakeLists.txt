cmake_minimum_required(VERSION 3.16)

# If you set any CMAKE_ variables, that can go here.
# (But usually don't do this, except maybe for C++ standard)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(
  DeviceConnectSDK_PAL
  VERSION 1.0
  LANGUAGES C CXX
)

# Add a static library DeviceConnectSDK
add_library(DeviceConnectSDK_PAL STATIC)

target_sources(DeviceConnectSDK_PAL 
  PRIVATE
    src/DeviceConnectSDK_PAL.cpp
    src/upload_data.cpp
    src/ws_mqtt.cpp
)