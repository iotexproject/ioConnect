#include <Arduino.h>
#include <DeviceConnect_Core.h>
#include <DeviceConnect_PAL.h>

#ifdef ESP32
#include <WiFi.h>
#elif defined(ESP8266)
#include <ESP8266WiFi.h>
#else
#error Platform not supported
#endif

#define TEST_UPLOAD_DATA 

#ifdef TEST_UPLOAD_DATA
#include "upload_data_test.h"
#endif

#define THINGNAME "133191882250001"
#define emptyString String()

const char ssid[] = "StayHungry";
const char pass[] = "zjn.19821225";

WiFiClient espClient;
DevConn_Comm  mqttClient(espClient);

void connectToWiFi(String init_str)
{
  if (init_str != emptyString)
    Serial.print(init_str);
  while (WiFi.status() != WL_CONNECTED)
  {
    Serial.print(".");
    delay(1000);
  }
  if (init_str != emptyString)
    Serial.println("ok!");
}

void setup() {
    
    Serial.begin(115200);
    delay(5000);
    Serial.println();

    WiFi.hostname(THINGNAME);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, pass);

    connectToWiFi(String("Attempting to connect to SSID: ") + String(ssid));  
 
    iotex_device_connect_sdk_init(&mqttClient);

}

void loop() {
  
  mqttClient.loop();

#ifdef TEST_UPLOAD_DATA

  iotex_upload_data_set_value(31, UPLOAD_DATA_CO2);
  iotex_upload_data_set_value(41, UPLOAD_DATA_TVOC);
  iotex_upload_data_set_value(515, UPLOAD_DATA_TEMP);
  iotex_upload_data_set_value(46, UPLOAD_DATA_HUMIDITY);

#endif

  delay(1000);

}

