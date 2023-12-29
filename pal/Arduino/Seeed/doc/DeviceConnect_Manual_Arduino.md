# DeviceConnect_Manual_Arduino



## Overview

The SDK is a software development toolkit for connecting IoT devices to Web3 nodes. It provides core components and a platform adaptation layer (PAL) for different development communities, including ESP32 and Arduino. This document will primarily focus on using the SDK for Arduino IDE platform development.



## Installation

1. Create a new project in the Arduino IDE development environment or use an existing Arduino project.

2. Copy the code of the core components (Core) and PAL components (PAL) to the `Arduino\libraries` directory of your project.

   ![LibDoc](.\image\LibDoc.png)

3. After restarting the Arduino IDE, you can find the two libraries under IDE – Sketch – Include Library. Alternatively, you can download them directly from the Library Manager.

   ![Library](.\image\Library.png)

   

## Configuration

Before using the SDK, you need to make some configurations to ensure its proper functioning：

1. In the SDK’s platform adaptation layer code (DeviceConnect_PAL_Config.h), make necessary configuration changes based on your device’s SN：

   - Device SN definition: **IOTEX_DEVICE_SN_USE_STATIC**

   

## Using the SDK

### Include the Header File

```c
#include <DeviceConnect_PAL.h>
```

### Create Communication Class Object

```c
DevConn_Comm  mqttClient(WiFiClientObject);
```

Where `WiFiClientObject` is an object of the `WiFiClient` class.



### Initialize the SDK

In the `setup()` function of your Arduino project, add the following code to initialize the SDK:

```c
void setup() {
    iotex_device_connect_sdk_init(&mqttClient);
}
```

This code will call the initialization function of the SDK to ensure its proper startup.



### Data Reporting

You can use the following API to report data:

- Developers can call the provided SDK APIs at appropriate places to send the data to be reported.

```c
/* Function Name: iotex_device_connect_upload_userdata
 * Function Parameters:
 *    buf : The starting address of the data packet to be sent
 *    buf_len : The length of the data to be sent
 *    type : Data packet type, the SDK currently supports three types of data
 *           IOTEX_USER_DATA_TYPE_JSON : The data packet is in JSON format
 *           IOTEX_USER_DATA_TYPE_PB   : The data packet is in ProtoBuf format
 *           IOTEX_USER_DATA_TYPE_RAW  : The data packet is in custom format
 * Function Return Value:
 *    IOTEX_DEV_ACCESS_ERR_SUCCESS : Data sent successfully
 *    IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER : Incorrect function input parameters
 *    IOTEX_DEV_ACCESS_ERR_BAD_STATUS : Device status error, the device has not completed the registration process
 *    IOTEX_DEV_ACCESS_ERR_NO_INIT : The SDK has not been initialized
*/
int iotex_device_connect_upload_userdata(void *buf, size_t buf_len, enum UserData_Type type);
```



## Example Code

Please refer to the following link for specific example code:

[deviceconnect-sdk/pal/Arduino/examples/DeviceConnect at main · machinefi/deviceconnect-sdk (github.com)](https://github.com/machinefi/deviceconnect-sdk/tree/main/pal/Arduino/examples/DeviceConnect)



## Conclusion 

This document provides a brief SDK usage manual, explaining how to use the SDK to connect to W3bStream nodes and send data on the Arduino IDE. Make necessary configurations and adjustments according to your project requirements. For further understanding of the SDK’s functionalities and APIs, please refer to the SDK’s documentation and example code.
