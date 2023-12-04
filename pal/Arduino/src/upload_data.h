#ifndef __DEVICE_CONNECT_SDK_PAL_DATA__
#define __DEVICE_CONNECT_SDK_PAL_DATA__

#include <Arduino.h>
#include "DeviceConnect_PAL_Config.h"

#define REGISTER_STATUS_NO_RESPONSE             0
#define REGISTER_STATUS_DEVICE_SHOULD_ENROLL    1
#define REGISTER_STATUS_DEVICE_CONFIRM_NEEDED   2
#define REGISTER_STATUS_DEVICE_SUCCESS          3
#define REGISTER_STATUS_USER_CONFIRM            4
#define REGISTER_STATUS_ALL                     5

#define UPLOAD_DATA_TEST_DEV_MAC_OFFSET         0

class DevConn_Data {
    private:
        int  _state;
        String _mac;
        char eth_address[32];
        char device_sn[18];  
        char wallet_address[64];
    public:
        DevConn_Data();
        ~DevConn_Data();

        void mac_set(String);
        String mac_get(void);
        void state_set(int);
        int  state_get(void);
        void wallet_address_set(char *buf, int buf_len); 
        char *wallet_address_get(void); 
        void device_sn_set(char *buf, int buf_len);
        char *device_sn_get(void);
        void eth_address_set(char *buf, int buf_len); 
        char *eth_address_get(void); 
};

extern DevConn_Data devconn_data;    

#endif