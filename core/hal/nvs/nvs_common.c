#include "include/hal/nvs/nvs_common.h"
#include "include/hal/nvs/soc/esp32/nvs_esp32.h"


extern nvs_drv *its_nvs;
void iotex_hal_nvs_drv_init(void) {

    its_nvs = &esp32_nvs;
    esp32_hal_nvs_init();
}