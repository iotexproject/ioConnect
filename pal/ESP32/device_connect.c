#include "device_connect.h"
#include "device_connect_config.h"

int iotex_device_connect_init(void) {

    default_SetSeed(esp_random());
    iotex_deviceconnect_sdk_core_init(time, iotex_mqtt_pubscription, iotex_mqtt_subscription);

    iotex_ws_comm_init();
    iotex_upload_data_init();    

    return 0;
}

int iotex_device_connect_upload_userdata(void *buf, size_t buf_len, enum UserData_Type type) {
    
    return iotex_dev_access_data_upload_with_userdata(buf, buf_len, type, iotex_devinfo_mac_get(DEV_MAC_TYPE_HEX));
}


