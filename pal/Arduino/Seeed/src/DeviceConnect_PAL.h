#pragma once

#include <Arduino.h>
#include "ws_mqtt.h"

class DevicePALClient {

public:
    DevicePALClient();
    ~DevicePALClient();

    void init(DevConn_Comm *commClient);
    void setMac(uint8_t *);    
    uint8_t* getMac(void);
};

extern DevicePALClient PalClient;

void iotex_device_connect_sdk_init(DevConn_Comm *commClient);
void iotex_device_connect_sdk_mac_set(uint8_t *mac);
uint8_t* iotex_device_connect_sdk_mac_get(void);
void iotex_device_connect_sdk_devSN_set(char *sn, int len);

