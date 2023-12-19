#ifndef __IOTEX_DEVICECONNECT_SDK__
#define __IOTEX_DEVICECONNECT_SDK__

#include "ws_mqtt.h"
#include "upload_data.h"
#include "DeviceConnect_Core.h"

int iotex_device_connect_init(void);
int iotex_device_connect_upload_userdata(void *buf, size_t buf_len, enum UserData_Type type);

#endif



