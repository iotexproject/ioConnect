set(PAL_SPROUT_DIR ../../../../pal/ESP32/Sprout)
set(PAL_DEVICE_REGISTER_DIR ../../../../pal/ESP32/DeviceRegister)

set(PAL_HEAD_PATH ${PAL_SPROUT_DIR} ${PAL_DEVICE_REGISTER_DIR})

file(GLOB PAL_SPROUT_SOURCES ${PAL_SPROUT_DIR}/*.c)
file(GLOB PAL_DEVICE_REGISTER_SOURCES ${PAL_DEVICE_REGISTER_DIR}/*.c)

set(PAL_SRC ${PAL_SPROUT_SOURCES} ${PAL_DEVICE_REGISTER_SOURCES})

idf_component_register(SRCS "ioConnect_main.c" "tcp_client_v4.c" ${PAL_SRC}
                    INCLUDE_DIRS "." ${PAL_HEAD_PATH})
