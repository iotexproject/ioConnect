#ifndef __IOTEX_HAL_NVS_COMMON__
#define __IOTEX_HAL_NVS_COMMON__

#include <stddef.h>
#include <stdio.h>

#include "include/common.h"

#ifdef IOTEX_PSA_ITS_NVS_C

#define IOTEX_HAL_NVS_KEY_SLOT_SIZE   128

typedef enum _iotex_nvs_open_mode_t {

    IOTEX_NVS_READONLY,
    IOTEX_NVS_READWRITE
}iotex_nvs_open_mode_t;

typedef unsigned int iotex_nvs_handle_t;

typedef int (*iotex_hal_nvs_open)(const char *namespace_name, iotex_nvs_open_mode_t open_mode, iotex_nvs_handle_t *out_handle);
typedef int (*iotex_hal_nvs_set_blob)(iotex_nvs_handle_t handle, const char *key, const void *value, size_t length);
typedef int (*iotex_hal_nvs_get_blob)(iotex_nvs_handle_t handle, const char *key, void *out_value, size_t *length);
typedef int (*iotex_hal_nvs_erase_key)(iotex_nvs_handle_t handle, const char *key);
typedef int (*iotex_hal_nvs_erase_all)(iotex_nvs_handle_t handle);
typedef int (*iotex_hal_nvs_commit)(iotex_nvs_handle_t handle);
typedef void (*iotex_hal_nvs_close)(iotex_nvs_handle_t handle);


typedef struct _nvs_drv
{
#ifdef IOTEX_FLASH_ENCRYPT
#ifdef IOTEX_CUSTOM_PARTITION
    char sec_partition_name[16];
#endif
#endif

    iotex_hal_nvs_open open;
    iotex_hal_nvs_close close;
    iotex_hal_nvs_set_blob set_blob;
    iotex_hal_nvs_get_blob get_blob;
    iotex_hal_nvs_erase_key erase_key;
    iotex_hal_nvs_erase_all erase_all;
    iotex_hal_nvs_commit commit;
}nvs_drv;

void iotex_hal_nvs_drv_init(void);

#endif
#endif