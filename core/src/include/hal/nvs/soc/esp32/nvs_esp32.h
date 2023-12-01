#ifndef __IOTEX_HAL_NVS_ESP32___
#define __IOTEX_HAL_NVS_ESP32___

#include "include/hal/nvs/nvs_common.h"

#define IOTEX_HAL_NVS_NAMESPACE_MAX_LENGTH  15

#ifdef ESP_PLATFORM
extern nvs_drv esp32_nvs;
#endif

int esp32_hal_nvs_init(void);

#endif