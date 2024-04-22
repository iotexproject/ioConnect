#ifdef ARDUINO
#include <Arduino.h>
#include <EEPROM.h>
#include "include/hal/flash/flash_common.h"
#include "include/hal/flash/soc/esp8266/flash.h"

static int esp8266_hal_flash_init(void) {

    return 0;

}

static int esp8266_hal_flash_earse(unsigned int address) {

    EEPROM.begin(ESP8266_FLASH_BLOCK_SIZE);

    for (int i = 0; i < ESP8266_FLASH_BLOCK_SIZE; i++) {
         EEPROM.write(i, 0); 
    }

    EEPROM.end();    
    
    return 0;
}

static int esp8266_hal_flash_write(unsigned int address, unsigned int offset, unsigned char *buf, int len) {

    unsigned int addr_w = address + offset;

    if (address + offset + len > ESP8266_FLASH_START_ADDRESS + ESP8266_FLASH_SIZE)
        return -1;

    if (NULL == buf)
        return -2;

    EEPROM.begin(len);        

    for (int i = 0; i < len; i++)
        EEPROM.write(addr_w + i, buf[i]);

    if (!EEPROM.commit()) {
        EEPROM.end();
        return -3;
    } 

    EEPROM.end();
    return len;

}

static int esp8266_hal_flash_read(unsigned int address, unsigned int offset, unsigned char *buf, int len) {

    unsigned int addr_w = address + offset;

    if (address + offset + len > ESP8266_FLASH_START_ADDRESS + ESP8266_FLASH_SIZE)
        return -1;

    if (NULL == buf)
        return -2;

    EEPROM.begin(len);        

    for (int i = 0; i < len; i++)
        buf[i] = EEPROM.read(addr_w + i);

    EEPROM.end();
    return len;
}

static int esp8266_hal_flash_protect(unsigned int protection) {

    return 0;
}

flash_drv esp8266_flash = {ESP8266_FLASH_START_ADDRESS, ESP8266_FLASH_SIZE, ESP8266_FLASH_BLOCK_SIZE,
                                esp8266_hal_flash_init, 
                                esp8266_hal_flash_earse, 
                                esp8266_hal_flash_write, 
                                esp8266_hal_flash_read, 
                                esp8266_hal_flash_protect};

#endif