#include <DeviceConnect_Core.h>
#include "upload_data.h"
#include "ws_mqtt.h"

static char app_mqtt_topic_status[128];
static char app_mqtt_token[64];
static char app_mqtt_url[64];
static char app_mqtt_topic[64];

static int  mqtt_state = WS_MQTT_STATUS_INIT;
static int  mqtt_server_type = 0;

static int8_t deviceMAC[6] = {0xb0, 0x25, 0xaa, 0x4f, 0xba, 0xaa};

void DevConn_Comm::state_set(int state) {
    if (state >= WS_MQTT_STATUS_MAX)
        return;

    mqtt_state = state;
}

char *DevConn_Comm::state_topic_get(void) {
    memset(app_mqtt_topic_status, 0, sizeof(app_mqtt_topic_status));
    sprintf(app_mqtt_topic_status, "%s/status/%s", app_mqtt_topic, devconn_data.mac_get().c_str());

    return app_mqtt_topic_status;
}

int parse_data_from_app_server(char *data, int data_len) {

    if (NULL == data || 0 == data_len)
        return -1;

    cJSON *json          = NULL;
    cJSON *json_status   = NULL;
    cJSON *json_proposer = NULL;

    json                 = cJSON_Parse(data);
    if (NULL == json)
        return -2;

    json_status = cJSON_GetObjectItem(json, "status");
    if (json_status == NULL || cJSON_IsFalse(json_status)) {
        return -3;
    }

    int status = json_status->valueint;

    if (1 == status) {
        json_proposer = cJSON_GetObjectItem(json, "proposer");
        if (json_proposer == NULL || cJSON_IsFalse(json_proposer)) {
            // ESP_LOGI(TAG, "Dev Proposer : False");
            return -3;
        }

        iotex_user_wallet_addr_set(json_proposer->valuestring, strlen(json_proposer->valuestring));
        devconn_data.wallet_address_set(json_proposer->valuestring, strlen(json_proposer->valuestring));
    }

    cJSON_Delete(json);

    return status;
}

int parse_data_from_token_server(char *data, int data_len)
{
    if (NULL == data || 0 == data_len)
        return -1;

    cJSON *json           = NULL;
    cJSON *json_data      = NULL;
    cJSON *json_data_item = NULL;

    json                  = cJSON_Parse(data);
    if (NULL == json)
        return -2;

    json_data = cJSON_GetObjectItem(json, "ok");
    if (json_data == NULL || cJSON_IsFalse(json_data)) {
        return -3;
    }

    json_data      = cJSON_GetObjectItem(json, "data");
    json_data_item = cJSON_GetObjectItem(json_data, "token");

    memset(app_mqtt_token, 0, 64);
    memcpy(app_mqtt_token, json_data_item->valuestring, strlen(json_data_item->valuestring));
    iotex_dev_access_set_token(json_data_item->valuestring, strlen(json_data_item->valuestring));

    json_data_item = cJSON_GetObjectItem(json_data, "mqtt_url");

    memset(app_mqtt_url, 0, 64);
    memcpy(app_mqtt_url, json_data_item->valuestring, strlen(json_data_item->valuestring));

    json_data_item = cJSON_GetObjectItem(json_data, "mqtt_topic");

    memset(app_mqtt_topic, 0, 64);
    memcpy(app_mqtt_topic, json_data_item->valuestring, strlen(json_data_item->valuestring));
    iotex_dev_access_set_mqtt_topic(json_data_item->valuestring, strlen(json_data_item->valuestring), 0);

    cJSON_Delete(json);

    return 0;
}

void DevConn_Comm::user_confirm(void) {

    this->state_set(WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_CONFIRM);
}

void DevConn_Comm::token_server_request(void) {

    char *message  = NULL;
    char *dev_sn = devconn_data.device_sn_get();
    if (NULL == dev_sn)
        return;

    cJSON *request = cJSON_CreateObject();

    cJSON_AddStringToObject(request, "project_name", WS_MQTT_TOKEN_SERVER_PROJECT_NAME);
    cJSON_AddStringToObject(request, "id", dev_sn);
    cJSON_AddStringToObject(request, "client_id", "seeed-001");

    message = cJSON_PrintUnformatted((const cJSON *)request);

    this->publish(WS_MQTT_TOKEN_SERVER_TOPIC, (uint8_t *)message, strlen(message), 0);
    this->state_set(WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED);

    if (message)
        free(message);

    cJSON_Delete(request);
}

//void token_message_received(char *topic, byte *payload, unsigned int length)
void messageReceived(uint8_t eventID, void* eventResult)
{
    struct eventResult *peventValue = (struct eventResult *)eventResult;

    switch (eventID)
    {
    case MQTT_EVENT_DATA:
        if (mqtt_server_type == MQTT_SERVER_TOKEN) {
            parse_data_from_token_server((char *)peventValue->ret.data.payload, peventValue->ret.data.len);
            mqtt_state = WS_MQTT_STATUS_TOKEN_SERVER_RECEIVED;
        }
        else {
            int status = parse_data_from_app_server((char *)peventValue->ret.data.payload, peventValue->ret.data.len);            
            devconn_data.state_set(status);
            if (1 == status) {
                mqtt_state = WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_CONFIRM;
            } else if (2 == status) {
                mqtt_state = WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_SUCCESS;
                iotex_dev_access_set_mqtt_status(IOTEX_MQTT_BIND_STATUS_OK);
            }
        }
            
        break;
    
    default:
        break;
    }

}

void DevConn_Comm::token_server_start(void) {

    while (!this->_mqttclient.connected()) {        

        if (this->_mqttclient.connect("gateway.w3bstream.com", 1883)) {
            printf("Token Server Connected!\n");
        } else {
            printf("failed, reason -> ");
            // pubSubErr(client.state());
      
            printf(" < try again in 5 seconds\n");
            delay(5000);
        }
    }

    mqtt_server_type = MQTT_SERVER_TOKEN;
    this->state_set(WS_MQTT_STATUS_TOKEN_SERVER_CONNECTED);
    this->subscribe("seeed-001");
    this->state_set(WS_MQTT_STATUS_TOKEN_SERVER_SUBSCRIBED);
}

void DevConn_Comm::app_server_start(void) {

    char app_mqtt_host[64] = {0};
    int urlLen = strlen(app_mqtt_url);
    if ((app_mqtt_url[0] == 'm') && (urlLen > (7 + 5))) {
        memcpy(app_mqtt_host, app_mqtt_url + 7, urlLen - 7 - 5);
    } else
        return;

    while (!this->_mqttclient.connected()) {        
        if (this->_mqttclient.connect(app_mqtt_host, 1883)) {
            printf("Webstream Server connected!\n");
        } else {
            printf("failed, reason -> ");
            // pubSubErr(client.state());
      
            printf(" < try again in 5 seconds\n");
            delay(5000);
        }
    }

    mqtt_server_type = MQTT_SERVER_APP;
    this->state_set(WS_MQTT_STATUS_APP_SERVER_CONNECTED);
    iotex_dev_access_set_mqtt_status(IOTEX_MQTT_CONNECTED);
}

void DevConn_Comm::loop(void) {

        if (!this->_mqttclient.connected()) {
            if (mqtt_server_type == MQTT_SERVER_TOKEN) {
                if (mqtt_state != WS_MQTT_STATUS_TOKEN_SERVER_FINISH)
                    this->state_set(WS_MQTT_STATUS_INIT);
                else
                    this->state_set(WS_MQTT_STATUS_APP_SERVER_START);
            } else if (mqtt_server_type == MQTT_SERVER_APP) {
                this->state_set(WS_MQTT_STATUS_APP_SERVER_RECONNECT);
            }

            iotex_dev_access_set_mqtt_status(IOTEX_MQTT_DISCONNECTED);
        }

        printf("mqtt state %d\n", mqtt_state);      
        switch (mqtt_state) {
            case WS_MQTT_STATUS_INIT:

                this->token_server_start();
                this->_mqttclient.setEventCallback(messageReceived);
    
                break;
            case WS_MQTT_STATUS_DEV_SN_READY:
                
                break;                
            case WS_MQTT_STATUS_TOKEN_SERVER_SUBSCRIBED:
            case WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED:

                token_server_request();
                this->state_set(WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED);

                break;
            case WS_MQTT_STATUS_TOKEN_SERVER_RECEIVED:

                this->_mqttclient.disconnect();
                this->state_set(WS_MQTT_STATUS_TOKEN_SERVER_FINISH);

                break;
            case WS_MQTT_STATUS_TOKEN_SERVER_FINISH:
            case WS_MQTT_STATUS_APP_SERVER_START:

                app_server_start();

                break;

            case WS_MQTT_STATUS_APP_SERVER_CONNECTED:

                this->subscribe(this->state_topic_get());
                this->state_set(WS_MQTT_STATUS_APP_SERVER_STATUS_SUBSCRIBED);

                break;

            case WS_MQTT_STATUS_APP_SERVER_STATUS_SUBSCRIBED:
                
                iotex_dev_access_query_dev_register_status(deviceMAC);
                
                break;
            case WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_CONFIRM:

                iotex_dev_access_dev_register_confirm(deviceMAC);
                iotex_dev_access_query_dev_register_status(deviceMAC);

                break;
            default:

                break;
        }

        this->_mqttclient.loop();
        
}

DevConn_Comm::DevConn_Comm(Client* client) :  _mqttclient(client){

}

DevConn_Comm::DevConn_Comm(Client& client) : _mqttclient(&client) {

}

DevConn_Comm::~DevConn_Comm() {
    
}

bool DevConn_Comm::publish(const char* topic, const uint8_t * payload, unsigned int plength, int qos) {

    this->_mqttclient.publish(topic, payload, plength);

    return true;
}

bool DevConn_Comm::subscribe(const char* topic) {

    this->_mqttclient.subscribe(topic);

    return true;
}


