#ifndef _WS_MQTT_H_
#define _WS_MQTT_H_

#include <Arduino.h>
#include <Client.h>
#include "TinyMqttClient.h"
#include "upload_data.h"

#define WS_MQTT_STATUS_INIT                                     0
#define WS_MQTT_STATUS_DEV_SN_READY                             1
#define WS_MQTT_STATUS_TOKEN_SERVER_CONNECTING                  2
#define WS_MQTT_STATUS_TOKEN_SERVER_CONNECTED                   3
#define WS_MQTT_STATUS_TOKEN_SERVER_SUBSCRIBED                  4
#define WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED                   5
#define WS_MQTT_STATUS_TOKEN_SERVER_RECEIVED                    6
#define WS_MQTT_STATUS_TOKEN_SERVER_FINISH                      7
#define WS_MQTT_STATUS_APP_SERVER_START                         8
#define WS_MQTT_STATUS_APP_SERVER_CONNECTED                     9
#define WS_MQTT_STATUS_APP_SERVER_STATUS_SUBSCRIBED             10
#define WS_MQTT_STATUS_APP_SERVER_STATUS                        11
#define WS_MQTT_STATUS_APP_SERVER_RECONNECT                     12
#define WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_CONFIRM           13
#define WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_SUCCESS           14
#define WS_MQTT_STATUS_MAX                                      15

#define WS_MQTT_TOKEN_SERVER_URL                                "mqtt://gateway.w3bstream.com:1883"
#define WS_MQTT_TOKEN_SERVER_TOPIC                              "project"
#define WS_MQTT_TOKEN_SERVER_SUBSCRIPTION_TOPIC                 "project"
#define WS_MQTT_TOKEN_SERVER_PROJECT_NAME                       "seeed-staging"     
#define WS_MQTT_TOKEN_SERVER_SUBSCRIPTION_TOPIC                 "project"

#define MQTT_SERVER_TOKEN   1
#define MQTT_SERVER_APP     2

class DevConn_Comm {
private:

    char *state_topic_get(void);

public:    
    DevConn_Comm(Client* client);
    DevConn_Comm(Client& client);
    ~DevConn_Comm();

    bool publish(const char* topic, const uint8_t * payload, unsigned int plength, int qos);
    bool subscribe(const char* topic);

    void user_confirm(void);
    void token_server_request(void);
    void app_server_start(void);
    void token_server_start(void);

    void loop(void);

    void state_set(int);
    
    TinyMqttClient _mqttclient;
};

#endif