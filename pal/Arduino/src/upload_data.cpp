#include <Arduino.h>
#include "upload_data.h"

DevConn_Data::DevConn_Data() {
    String devsn(REGISTER_DEV_STATIC_SN);
    memcpy(this->device_sn, devsn.c_str(), sizeof(this->device_sn));
 
    this->_state = -1;
}

DevConn_Data::~DevConn_Data() {
    this->_state = -1;
}

void DevConn_Data::mac_set(String mac) {
    this->_mac = mac;
}

String DevConn_Data::mac_get(void) {
    return this->_mac;
}

int DevConn_Data::state_get(void) {
    return this->_state;
}

void DevConn_Data::state_set(int state) {
    this->_state = state > this->_state ? state : this->_state;
}

void DevConn_Data::wallet_address_set(char *buf, int buf_len) 
{
    if ( buf == NULL || buf_len == 0)
        return;

    memset(wallet_address, 0, 64);
    memcpy(wallet_address, buf, buf_len);
}

char *DevConn_Data::wallet_address_get(void) 
{
    if (wallet_address[0])
        return wallet_address;

    return NULL;
}

void DevConn_Data::device_sn_set(char *buf, int buf_len) {

    if ( buf == NULL || buf_len == 0)
        return;

    memset(device_sn, 0, 18);
    memcpy(device_sn, buf, buf_len);   
}

char *DevConn_Data::device_sn_get() {

    if (device_sn[0])
        return device_sn;

    return NULL;
}

void DevConn_Data::eth_address_set(char *buf, int buf_len) {

    if ( buf == NULL || buf_len == 0)
        return;

    memset(eth_address, 0, 32);
    memcpy(eth_address, buf, buf_len);
    
}

char *DevConn_Data::eth_address_get() {

    if (eth_address[0])
        return eth_address;

    return NULL;
}

DevConn_Data devconn_data; 