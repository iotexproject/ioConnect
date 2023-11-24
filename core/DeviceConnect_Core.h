#ifndef __WSIOTSDK_H__
#define __WSIOTSDK_H__

#include "include/psa/crypto.h"
#include "include/utils/iotex_dev_access.h"
#include "include/utils/LowerS/LowerS.h"

uint8_t * iotex_deviceconnect_sdk_core_init(iotex_gettime get_time_func, iotex_mqtt_pub mqtt_pub, iotex_mqtt_sub mqtt_sub);
uint8_t * iotex_wsiotsdk_get_public_key(void);
uint8_t * iotex_wsiotsdk_get_eth_addr(void);

#endif
