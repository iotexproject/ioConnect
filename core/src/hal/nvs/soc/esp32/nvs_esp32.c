#include <string.h>
#ifdef ESP_PLATFORM
#include "nvs_flash.h"
#endif
#include "include/hal/nvs/nvs_common.h"
#include "include/hal/nvs/soc/esp32/nvs_esp32.h"

#ifdef ESP_PLATFORM
static int esp32_hal_nvs_open(const char *namespace_name, iotex_nvs_open_mode_t open_mode, iotex_nvs_handle_t *out_handle) {

    if (strlen(namespace_name) > IOTEX_HAL_NVS_NAMESPACE_MAX_LENGTH)
        return -1;

    esp_err_t ret = nvs_open(namespace_name, (nvs_open_mode_t)open_mode, (nvs_handle_t *)out_handle);
#ifdef IOTEX_HAL_DEBUG    
    printf("nvs_open [%d] : %s\n", *out_handle, esp_err_to_name(ret));
#endif    
    return ret;
}

static int esp32_hal_nvs_erase_key(iotex_nvs_handle_t handle, const char *key) {

    return nvs_erase_key((nvs_handle_t) handle, key);
}

static int esp32_hal_nvs_erase_all(iotex_nvs_handle_t handle) {

    return nvs_erase_all((nvs_handle_t) handle);
}

static int esp32_hal_nvs_set_blob(iotex_nvs_handle_t handle, const char *key, const void *value, size_t length) {

    esp_err_t ret = nvs_set_blob((nvs_handle_t) handle, key, value, length);
#ifdef IOTEX_HAL_DEBUG    
    printf("nvs_set_blob [%d:%s]: %s\n", handle, key, esp_err_to_name(ret));
#endif
    if (ret == ESP_OK)
        return length;

    return -152;
}

static int esp32_hal_nvs_get_blob(iotex_nvs_handle_t handle, const char *key, void *out_value, size_t *length) {

    esp_err_t err = nvs_get_blob((nvs_handle_t) handle, key, out_value, length);
#ifdef IOTEX_HAL_DEBUG      
    printf("nvs_get_blob : %s\n", esp_err_to_name(err));
#endif
    if (err == ESP_OK)
        return err;

    return -152;
}

static int esp32_hal_nvs_commit(iotex_nvs_handle_t handle) {

    esp_err_t ret = nvs_commit((nvs_handle_t) handle);
#ifdef IOTEX_HAL_DEBUG      
    printf("nvs_commit : %s\n", esp_err_to_name(ret));
#endif
    return ret;
}

static void esp32_hal_nvs_close(iotex_nvs_handle_t handle) {

    nvs_close((nvs_handle_t) handle);

}

nvs_drv esp32_nvs = {   esp32_hal_nvs_open, 
                        esp32_hal_nvs_close, 
                        esp32_hal_nvs_set_blob, 
                        esp32_hal_nvs_get_blob, 
                        esp32_hal_nvs_erase_key,
                        esp32_hal_nvs_erase_all,
                        esp32_hal_nvs_commit};

int esp32_hal_nvs_init(void) {


	esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    return 0;
}
#endif
                               

