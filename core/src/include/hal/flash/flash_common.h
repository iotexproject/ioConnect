#ifndef __IOTEX_HAL_FLASH_COMMON__
#define __IOTEX_HAL_FLASH_COMMON__

#ifdef ARDUINO
#define IOTEX_HAL_FLASH_ESP8266_ARDUINO
#else
#define IOTEX_HAL_FLASH_ESP32S3
#endif

#ifdef IOTEX_HAL_FLASH_ESP8266_ARDUINO
#define IOTEX_HAL_FLASH_KEY_SLOT_SIZE   128
#else 
#ifdef IOTEX_HAL_FLASH_ESP32S3
#define IOTEX_HAL_FLASH_KEY_SLOT_SIZE   128
#endif
#endif

typedef int (*iotex_hal_flash_init)(void);
typedef int (*iotex_hal_flash_earse)(unsigned int address);
typedef int (*iotex_hal_flash_write)(unsigned int address, unsigned int offset, unsigned char *buf, int len);
typedef int (*iotex_hal_flash_read)(unsigned int address, unsigned int offset, unsigned char *buf, int len);
typedef int (*iotex_hal_flash_protect)(unsigned int protection);

typedef struct _flash_drv
{
    unsigned int start_address;
    unsigned int flash_size;
    unsigned int block_size;

    /* data */
    iotex_hal_flash_init init;
    iotex_hal_flash_earse earse;
    iotex_hal_flash_write write;
    iotex_hal_flash_read  read;
    iotex_hal_flash_protect protect;

}flash_drv;

void iotex_hal_flash_drv_init(void);

#endif