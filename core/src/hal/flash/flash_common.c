#include "include/common.h"

#ifdef IOTEX_PSA_ITS_FLASH_C

#include "include/hal/flash/flash_common.h"

#ifdef IOTEX_HAL_FLASH_ESP8266_ARDUINO
#include "include/hal/flash/soc/esp8266/flash.h"
#endif

#ifdef IOTEX_HAL_FLASH_ESP32S3
#include "include/hal/flash/soc/esp32/flash.h"
#endif

extern flash_drv *its_flash;
void iotex_hal_flash_drv_init(void) {

#ifdef IOTEX_HAL_FLASH_ESP8266_ARDUINO
    its_flash = &esp8266_flash;
#endif    

#ifdef IOTEX_HAL_FLASH_ESP32S3
    its_flash = &esp32_flash;
#endif

}

#endif