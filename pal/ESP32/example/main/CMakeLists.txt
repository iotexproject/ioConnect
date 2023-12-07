set(PAL_DIR ./DeviceConnect_PAL)
file(GLOB_RECURSE PAL_SOURCES ${PAL_DIR}/*.c)

idf_component_register(SRCS "DeviceConnect_main.c" ${PAL_SOURCES}
                    INCLUDE_DIRS "." ${PAL_DIR})
