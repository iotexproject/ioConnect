# DeviceConnect_PAL Manual for ESP32



## Overview

This SDK is a software development toolkit for connecting IoT devices to Web3 nodes. It provides core components and a platform adaptation layer (PAL) for different development communities, including ESP32 and Arduino. This document will primarily focus on using the SDK for ESP32 platform development.

## Installation

1. Create a new project in the ESP32 development environment or use an existing ESP32 project.

2. Copy the code of the core components (Core) to the `components` directory of your project. Make sure the core components are compiled and linked as part of the ESP32 components. Alternatively, you can download the IoTex PSACrypto component from the component library.

   [IDF Component Registry (espressif.com)](https://components.espressif.com/components/iotex-embedded/psacrypto)

3. Copy the code of the platform adaptation layer (PAL) to the `main` directory of your project. This layer will be the main code file of your project for compilation and execution.

   For example, developers can add the following code to the CMakeLists.txt file in the main directory to ensure that the PAL is included in the compilation:

   ```cmake
   set(PAL_DIR ./pal)
   file(GLOB_RECURSE PAL_SOURCES ${PAL_DIR}/*.c)
   
   idf_component_register(
     SRCS "main.c" ${PAL_SOURCES}
     INCLUDE_DIRS "."  ${PAL_DIR})
   ```

   

## Configuration

Before using the SDK, you need to make some configurations to ensure its proper functioning:

1. Configure the ESP32 development environment, including installing appropriate drivers and toolchains.

   [ESP32-S3-DevKitM-1 - ESP32-S3 - — ESP-IDF Programming Guide latest documentation (espressif.com)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/hw-reference/esp32s3/user-guide-devkitm-1.html)

2. In the SDK’s platform adaptation layer code (device_connect_config.h), make necessary configuration changes based on your requirements, such as:

   - Whether to enable the functionality of the Standard Layer code. [IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER]

   - Definition of event parameters for data reporting on the Standard Layer:

     - Data event loop definition：STANDARD_LAYER_EVENT_LOOP

     - Data event base definition：STANDARD_LAYER_EVENT_BASE

     - Data event ID：STANDARD_LAYER_EVENT_ID

     The above definitions should align with your original data event design. If your project does not use ESP EVENT or have no need for it, this configuration can be ignored.

   - Device SN definition：IOTEX_DEVICE_SN_USE_STATIC
   
     

## Using the SDK

### Initializing the SDK

In the `main.c` file of your ESP32 project, add the following code to initialize the SDK:

```c
#include "device_connect.h"

void app_main() {
    iotex_ioconnect_sdk_init();
    // ...
}
```

This code will call the initialization function of the SDK to ensure its proper startup.



### Handling Data Events

There are two ways to report sensor data from your device to the W3bStream node using the SDK:

- If your new or existing project uses the ESP32 event handling mechanism, you can use the SDK’s Standard Layer.
- If your new or existing project does not use the ESP32 event handling mechanism, you can directly call the SDK’s APIs.

#### Standard Layer:

- Follow the instructions in the Configuration section to fill in the configuration file (device_connect_config.h) with the ESP EVENT-related information you use.
- Modify the example IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER_TEST code in the configuration file to suit your needs, mainly handling the data structure to be sent.

#### API：

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



### Handling Device Status Events

After initializing the SDK, it will automatically determine whether the device has completed the registration process. The SDK will send device status information to the developer through Event events.

#### Obtaining Device Status Information

Developers can subscribe to events using the `esp_event_handler_instance_register_with` function to obtain device status information. Here is an example:

```c
#include "esp_event.h"
#include "device_connect.h"

ESP_ERROR_CHECK(esp_event_handler_instance_register_with(register_status_event_handle,

                              REGISTER_STATUS_EVENT_BASE,  ESP_EVENT_ANY_ID,

                               __xxx_event_handler, NULL, NULL));   
```

- Replace `__xxx_event_handler` with your custom event handling function.
- Developers can obtain the following device status:
  - REGISTER_STATUS_NO_RESPONSE								// No response from the device to the Web3 node
  - REGISTER_STATUS_DEVICE_SHOULD_ENROLL            // User needs to register the device on the portal page
  - REGISTER_STATUS_DEVICE_CONFIRM_NEEDED		  // User needs to confirm the device on the portal page
  - REGISTER_STATUS_DEVICE_SUCCESS    						// Device status is normal
  - REGISTER_STATUS_USER_CONFIRM     						 // User needs to confirm relevant information on the device
- Developers can respond to zero or more device statuses based on project requirements or implementation methods.

#### Obtaining Device and User Information

Developers can subscribe to events using the `esp_event_handler_instance_register_with` function to obtain device/user status information. Here is an example:

```c
#include "esp_event.h"
#include "device_connect.h"

ESP_ERROR_CHECK(esp_event_handler_instance_register_with(ws_para_event_handle,

                              WS_PARA_EVENT_BASE,  ESP_EVENT_ANY_ID,

                               __xxx_event_handler, NULL, NULL));   
```

- Replace `__xxx_event_handler` with your custom event handling function.

- Developers can obtain the following device status:
  - WS_PARA_WALLET_ADDRESS						// Wallet address associated with the user
  - WS_PARA_ETH_ADDRESS                               // ETH address associated with the device
- Developers can respond to zero or more device statuses based on project requirements or implementation methods.



## Example Code

Please refer to the following link for specific example code:

[machinefi/seeed-indicator: The firmware for connecting the Seeed Studio's SenseCAP Indicator to W3bstream (github.com)](https://github.com/machinefi/seeed-indicator)



## Summarize

This document provides a brief SDK usage manual, explaining how to use the SDK to connect to W3bStream nodes and send data on the ESP32. Make necessary configurations and adjustments according to your project requirements. For further understanding of the SDK’s functionalities and APIs, please refer to the SDK’s documentation and example code.
