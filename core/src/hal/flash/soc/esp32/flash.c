#ifdef ESP_PLATFORM
#include "nvs_flash.h"
#include "include/hal/flash/flash_common.h"
#include "include/hal/flash/soc/esp32/flash.h"

static int esp32_hal_flash_init(void) {

	return nvs_flash_init();
    
}

static int esp32_hal_flash_earse(unsigned int address) {
    
    return 0;
}

static int esp32_hal_flash_write(unsigned int address, unsigned int offset, unsigned char *buf, int len) {

    return len;

}

static int esp32_hal_flash_read(unsigned int address, unsigned int offset, unsigned char *buf, int len) {

    return len;
}

static int esp32_hal_flash_protect(unsigned int protection) {

    return 0;
}

flash_drv esp32_flash = {ESP32_FLASH_START_ADDRESS, ESP32_FLASH_SIZE, ESP32_FLASH_BLOCK_SIZE,
                                esp32_hal_flash_init, 
                                esp32_hal_flash_earse, 
                                esp32_hal_flash_write, 
                                esp32_hal_flash_read, 
                                esp32_hal_flash_protect};

#endif
