#include <Arduino.h>

#include <stdio.h>
#include <time.h>

#include "DeviceConnect_PAL.h"
#include "DeviceConnect_Core.h"

int iotex_device_connect_sdk_init(DevConn_Comm *commClient) {

    iotex_deviceconnect_sdk_core_init(commClient);
    return 0;
}