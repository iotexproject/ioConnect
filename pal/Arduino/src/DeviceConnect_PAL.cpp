#include <Arduino.h>

#include <stdio.h>
#include <time.h>

#include "DeviceConnect_PAL.h"
#include "DeviceConnect_Core.h"

static uint8_t macAddress[6];

static void hex2str(uint8_t *input, uint32_t input_len, char *output) {
    char *hexEncode = (char *)"0123456789abcdef";
    int j = 0;

    for (int i = 0; i < input_len; i++) {
        output[j++] = hexEncode[(input[i] >> 4) & 0xf];
        output[j++] = hexEncode[(input[i]) & 0xf];
    }
}

DevicePALClient::DevicePALClient() {

}

DevicePALClient::~DevicePALClient() {

}

void DevicePALClient::init(DevConn_Comm *commClient) {
    iotex_deviceconnect_sdk_core_init(commClient);
}

void DevicePALClient::setMac(uint8_t *mac) {

    String macstr((char *)mac);

    if (mac) {
        memcpy(macAddress, mac, 6);
        devconn_data.mac_set(macstr);
    }
}

uint8_t* DevicePALClient::getMac(void) {
    return macAddress; 
}

DevicePALClient PalClient;

void iotex_device_connect_sdk_init(DevConn_Comm *commClient) {
    iotex_deviceconnect_sdk_core_init(commClient);
}

void iotex_device_connect_sdk_mac_set(uint8_t *mac) {

    char mac_addr[15] = {0};

    if (NULL == mac)
        return;

    hex2str(mac, 6, mac_addr);

    printf("MAC : %s\n", mac_addr);
    String macStr(mac_addr);

    memcpy(macAddress, mac, 6);
    devconn_data.mac_set(macStr);
}

uint8_t* iotex_device_connect_sdk_mac_get(void) {

    if (macAddress[0])
        return macAddress;

    return NULL;
}

void iotex_device_connect_sdk_devSN_set(char *sn, int len) {

    if (sn) 
        devconn_data.device_sn_set(sn, len);
}



