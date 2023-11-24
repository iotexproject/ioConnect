#ifndef __IOTEX_HAL_FLASH__
#define __IOTEX_HAL_FLASH__

#define ESP8266_FLASH_START_ADDRESS     0
#define ESP8266_FLASH_SIZE              512
#define ESP8266_FLASH_BLOCK_SIZE        ESP8266_FLASH_SIZE

extern flash_drv esp8266_flash;

#endif