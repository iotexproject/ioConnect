#ifndef __IOTEX_HAL_FLASH__
#define __IOTEX_HAL_FLASH__

#define ESP32_FLASH_START_ADDRESS     0
#define ESP32_FLASH_SIZE              512
#define ESP32_FLASH_BLOCK_SIZE        ESP32_FLASH_SIZE

extern flash_drv esp32_flash;

#endif