
zephyr_include_directories(include)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/DIDs/dids.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Sprout/sprout.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/DeviceRegister/deviceregister.c)
