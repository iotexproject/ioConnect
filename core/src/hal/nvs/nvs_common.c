#include "include/hal/nvs/nvs_common.h"
#ifdef ESP_PLATFORM
#include "include/hal/nvs/soc/esp32/nvs_esp32.h"
#endif

#ifdef ESP_PLATFORM
extern nvs_drv *its_nvs;
#endif
void iotex_hal_nvs_drv_init(void) {
#ifdef ESP_PLATFORM
    its_nvs = &esp32_nvs;
    esp32_hal_nvs_init();
#endif    
}