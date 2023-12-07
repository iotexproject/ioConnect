#ifndef __UPLOAD_DATA_H__
#define __UPLOAD_DATA_H__

#include "esp_event.h"

struct dev_mac {
    int valid;
    char mac[6];
    char mac_str[16];
};

enum dev_mac_type {
    DEV_MAC_TYPE_HEX,
    DEV_MAC_TYPE_STR,
};

enum REGISTER_STATUS_EVENT_DEFINE {

    REGISTER_STATUS_NO_RESPONSE           = 0,
    REGISTER_STATUS_DEVICE_SHOULD_ENROLL  = 1,
    REGISTER_STATUS_DEVICE_CONFIRM_NEEDED = 2,
    REGISTER_STATUS_DEVICE_SUCCESS        = 3,
    REGISTER_STATUS_USER_CONFIRM          = 4,

    REGISTER_STATUS_ALL,
};

enum WS_PARA_EVENT_DEFINE {

    WS_PARA_WALLET_ADDRESS = 0,
    WS_PARA_ETH_ADDRESS    = 1,

    WS_PARA_ALL,
};

#define UPLOAD_DATA_TEST_DEV_MAC_OFFSET             0

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER    
ESP_EVENT_DECLARE_BASE(REGISTER_STATUS_EVENT_BASE);
extern esp_event_loop_handle_t register_status_event_handle;
#endif

ESP_EVENT_DECLARE_BASE(WS_PARA_EVENT_BASE);
extern esp_event_loop_handle_t ws_para_event_handle;

char *iotex_devinfo_mac_get(enum dev_mac_type);
char *iotex_devinfo_dev_sn_get(void);
int iotex_devinfo_query_dev_sn(void);
void iotex_upload_data_set_status(int status);
void iotex_wallet_address_send(char *buf, int buf_len); 
char *iotex_wallet_address_get(void); 
void iotex_eth_address_send(char *buf, int buf_len); 
char *iotex_eth_address_get(void); 

#endif