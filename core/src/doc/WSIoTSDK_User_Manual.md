

# 0. Update Notes

**WSIoTSDK_20230518a**

- Merged **IoTeX-DevRegister** and **WSIoTSDK**.
- Add the ability to communicate with w3bstream devnet.

**WSIoTSDK_20230317a**

- Optimized random number generation mechanism, added entropy pool, timestamp, custom string as random number seed function (NISP NIST SP 800-90A compliant)

**IoTeX-DevRegister_20230317b**

- Added simulated pebble data from user space to library space, the library state machine now supports triggered sending of data, please refer to 4.2 for specific functions.

**IoTeX-DevRegister_20230317a**

- Added simulated pebble data uplink function, uplink data can be seen on portal now.
- Added simulated pebble configuration reporting function.

**IoTeX-DevRegister_20230310a**

- Add device id setting function, device id can be set dynamically by user in runtime, if not set then use IOTEX_DEVICE_ID to define the value.
- The debug enable function has been added to allow users to dynamically enable debug messages.

**WSIoTSDK_20230310a**

- Add signature key reset function to facilitate users to conduct random key test.

- Fix the bug of signature check error in the test code.

- Fix the bug that the signature key cannot be generated randomly.

- Fix the bug in the logic of generating signature key.

  

# 1. Include header files

Headers to be included in the main program.

| Headers                | Notes                                                        | Libs     |
| ---------------------- | ------------------------------------------------------------ | -------- |
| \#include <wsiotsdk.h> | The only header file that needs to be introduced to the user code | WSIoTSDK |



# 2. How to use the WSIoTSDK library

## 2.1 Functions that need to be registered

| Function Prototype                                           | Effects                              | Register API        |
| ------------------------------------------------------------ | ------------------------------------ | ------------------- |
| time_t (*iotex_gettime)(void)                                | Get the current timestamp            | iotex_deviceconnect_sdk_core_init |
| int (*iotex_mqtt_pub)(char *, unsigned char *, unsigned int , unsigned char) | External MQTT Publishing Functions   | iotex_deviceconnect_sdk_core_init |
| int (*iotex_mqtt_sub)(char *);                               | External MQTT Subscription Functions | iotex_deviceconnect_sdk_core_init |

### Example

```c
int iotex_mqtt_pubscription(char *topic, unsigned char *buf, unsigned int buflen, unsigned char qos) {

    return client.publish(topic, (const uint8_t *)buf, buflen, false);

}

int iotex_mqtt_subscription(char *topic) {

    return client.subscribe(topic);
}

time_t iotex_time_set_func(void)
{
    return time(nullptr);
}    

iotex_deviceconnect_sdk_core_init(iotex_time_set_func, iotex_mqtt_pubscription, iotex_mqtt_subscription);
```

## 2.2 API Reference

| Name                             | Effects                                        | Call Timing                                                  | Notes    |
| -------------------------------- | ---------------------------------------------- | ------------------------------------------------------------ | -------- |
| iotex_deviceconnect_sdk_core_init              | WSIotSDK initialization                        | Before using any of the WSIotSDK library functions           | Required |
| iotex_dev_access_set_mqtt_status | MQTT State Settings                            | When mqtt connection is successful, disconnected, etc.       | Required |
| iotex_dev_access_mqtt_input      | MQTT Receive Message Processing Function Entry | When an MQTT message is received                             | Optional |
| iotex_dev_access_enable          | Debug Logging Enabled                          | Must be followed by iotex_deviceconnect_sdk_core_init to enable the user to dynamically enable debug log | Optional |
| iotex_import_key                 | Importing a signature Keys                     | Must be followed by iotex_deviceconnect_sdk_core_init.                     | Required |



## 2.3 Macro definitions to be configured

| Name                     | Effects | Location                  | Notes    |
| ------------------------ | ------- | ------------------------- | -------- |
| IOTEX_TOKEN_DEFAULTT     | Token   | iotex_dev_access_config.h | Required |
| IOTEX_MQTT_TOPIC_DEFAULT | Topic   | iotex_dev_access_config.h | Required |

### Examples：

```c
#define IOTEX_TOKEN_DEFAULT				"CI6IkpXVCJ9.eyJQYXlsb2FkIjoiOTAyNjI5NzAzNTU1OTkzOCIsImlzcyI6InczYnN0cmVhbS"
#define IOTEX_MQTT_TOPIC_DEFAULT		"eth_0x31c3785bebe03cc5ba691c486d6d1cdf8bb438c4_esp32_hello"
```



# 3. Key import

The WSIoTSDK library currently provides three ways to import signature keys:

| Macro Definition              | Description                           | Rules                                  | Notes                                       |
| ----------------------------- | ------------------------------------- | -------------------------------------- | ------------------------------------------- |
| IOTEX_SIGNKEY_USE_STATIC_DATA | Using the hard compilation method     | Directly into the project by compiling | Requires external generation of Private Key |
| IOTEX_SIGNKEY_USE_EEPROM      | Using the Key stored in the EEPROM    |                                        | ESP32 is not available                      |
| IOTEX_SIGNKEY_USE_PRNG        | Generated using pseudo-random numbers | Determined by the user's unique seed   | User needs to define IOTEX_SEED_USER_DEFINE |



