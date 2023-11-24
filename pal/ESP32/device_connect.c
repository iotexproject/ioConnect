#include "device_connect.h"
#include "device_connect_config.h"

int iotex_device_connect_init(void) {

    default_SetSeed(esp_random());
    iotex_wsiotsdk_init(time, iotex_mqtt_pubscription, iotex_mqtt_subscription);

    iotex_ws_comm_init();
    iotex_upload_data_init();    

    return 0;
}


