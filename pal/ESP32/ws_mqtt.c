#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "mqtt_client.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"

#include "upload_data.h"
#include "ws_mqtt.h"
#include "DeviceConnect_Core.h"

// #include "view_data.h"

static const char *TAG = "ws_mqtt";

static SemaphoreHandle_t __g_mqtt_task_sem;
static SemaphoreHandle_t __g_mqtt_status_sem;

static char app_mqtt_token[64]           = {0};
static char app_mqtt_url[64]             = {0};
static char app_mqtt_topic[64]           = {0};
static char app_mqtt_topic_status[128]   = {0};

static enum mqtt_server_type server_type = MQTT_SERVER_TOKEN;

esp_mqtt_client_handle_t mqtt_client     = NULL;
static int               mqtt_status     = WS_MQTT_STATUS_INIT;

ESP_EVENT_DEFINE_BASE(MQTT_EVENT_BASE);
esp_event_loop_handle_t mqtt_event_handle_t;

static void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0) {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}

static void hex2str(char *buf_hex, int len, char *str)
{
    int        i, j;
    const char hexmap[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for (i = 0, j = 0; i < len; i++) {
        str[j++] = hexmap[buf_hex[i] >> 4];
        str[j++] = hexmap[buf_hex[i] & 0x0F];
    }
    str[j] = 0;
}

static void ws_mqtt_set_status(uint8_t status)
{

    if (status >= WS_MQTT_STATUS_MAX)
        return;

    xSemaphoreTake(__g_mqtt_status_sem, portMAX_DELAY);
    mqtt_status = status;
    xSemaphoreGive(__g_mqtt_status_sem);
}

static char *ws_mqtt_get_status_topic(void)
{

    memset(app_mqtt_topic_status, 0, sizeof(app_mqtt_topic_status));
    sprintf(app_mqtt_topic_status, "%s/status/%s", app_mqtt_topic, iotex_devinfo_mac_get(DEV_MAC_TYPE_STR));

    ESP_LOGI(TAG, "Status Topic %s", app_mqtt_topic_status);

    return app_mqtt_topic_status;
}

static int ws_mqtt_token_server_parse_data(char *data, int data_len)
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
        ESP_LOGI(TAG, "Token Server : False\n");
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

static int ws_mqtt_app_server_parse_data(char *data, int data_len)
{

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
        ESP_LOGI(TAG, "Dev Status : False");
        return -3;
    }

    int status = json_status->valueint;
    ESP_LOGI(TAG, "Dev Status : %d", status);

    if (1 == status) {
        json_proposer = cJSON_GetObjectItem(json, "proposer");
        if (json_proposer == NULL || cJSON_IsFalse(json_proposer)) {
            ESP_LOGI(TAG, "Dev Proposer : False");
            return -3;
        }

        iotex_user_wallet_addr_set(json_proposer->valuestring, strlen(json_proposer->valuestring));
        iotex_wallet_address_send(json_proposer->valuestring, strlen(json_proposer->valuestring));

        ESP_LOGI(TAG, "Dev Proposer : %s", json_proposer->valuestring);
    }

    cJSON_Delete(json);

    return status;
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%d", base, event_id);
    esp_mqtt_event_handle_t  event  = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int                      msg_id;

    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED Server Type %d", *(enum mqtt_server_type *)handler_args);

            if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_TOKEN) {
#ifdef WS_MQTT_HANDLE_USE_STATUS_MACHINE
                ws_mqtt_set_status(WS_MQTT_STATUS_TOKEN_SERVER_CONNECTED);
                iotex_mqtt_subscription("seeed-001");
#endif
#ifdef WS_MQTT_HANDLE_USE_EVENT
                esp_event_post_to(mqtt_event_handle, MQTT_EVENT_BASE, WS_MQTT_STATUS_TOKEN_SERVER_CONNECTED, NULl, 0, portMAX_DELAY);
#endif
            } else if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_APP) {
                ws_mqtt_set_status(WS_MQTT_STATUS_APP_SERVER_CONNECTED);
                iotex_dev_access_set_mqtt_status(IOTEX_MQTT_CONNECTED);
            }

            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");

            if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_TOKEN) {
#ifdef WS_MQTT_HANDLE_USE_STATUS_MACHINE
                if (WS_MQTT_STATUS_TOKEN_SERVER_FINISH != mqtt_status)
                    ws_mqtt_set_status(WS_MQTT_STATUS_INIT);
                else
                    ws_mqtt_set_status(WS_MQTT_STATUS_APP_SERVER_START);
#endif
#ifdef WS_MQTT_HANDLE_USE_EVENT
                esp_event_post_to(mqtt_event_handle, MQTT_EVENT_BASE, WS_MQTT_STATUS_INIT, NULl, 0, portMAX_DELAY);
#endif
            } else if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_APP) {
                ws_mqtt_set_status(WS_MQTT_STATUS_APP_SERVER_RECONNECT);
            }

            iotex_dev_access_set_mqtt_status(IOTEX_MQTT_DISCONNECTED);

            break;

        case MQTT_EVENT_SUBSCRIBED:

            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);

            if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_TOKEN)
#ifdef WS_MQTT_HANDLE_USE_STATUS_MACHINE
                ws_mqtt_set_status(WS_MQTT_STATUS_TOKEN_SERVER_SUBSCRIBED);
            else if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_APP) {
                ws_mqtt_set_status(WS_MQTT_STATUS_APP_SERVER_STATUS_SUBSCRIBED);
            }
#endif
#ifdef WS_MQTT_HANDLE_USE_EVENT
            esp_event_post_to(mqtt_event_handle, MQTT_EVENT_BASE, WS_MQTT_STATUS_INIT, NULl, 0, portMAX_DELAY);
#endif

            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);

            if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_TOKEN) {
                ws_mqtt_set_status(WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED);
            }

            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);

            if (*(enum mqtt_server_type *)handler_args == MQTT_SERVER_TOKEN) {
                ws_mqtt_token_server_parse_data((char *)event->data, (int)event->data_len);
                ws_mqtt_set_status(WS_MQTT_STATUS_TOKEN_SERVER_RECEIVED);
            } else {
                int status = ws_mqtt_app_server_parse_data((char *)event->data, (int)event->data_len);
                iotex_upload_data_set_status(status);
                if (2 == status) {
                    ws_mqtt_set_status(WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_SUCCESS);
                    iotex_dev_access_set_mqtt_status(IOTEX_MQTT_BIND_STATUS_OK);
                }
            }

            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
                log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
                log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
                log_error_if_nonzero("captured as transport's socket errno", event->error_handle->esp_transport_sock_errno);
                ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
            }
            break;
        default:
            ESP_LOGI(TAG, "Other event id:%d", event->event_id);
            break;
    }
}

static void ws_mqtt_token_server_start(void)
{

    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri             = "mqtt://gateway.w3bstream.com:1883",
        .network.disable_auto_reconnect = true,
    };

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (NULL == mqtt_client)
        ESP_LOGE(TAG, "mqtt client init error");

    server_type = MQTT_SERVER_TOKEN;

    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, &server_type);
    esp_mqtt_client_start(mqtt_client);
}

static void __register_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data)
{
    switch (id) {
        case REGISTER_STATUS_USER_CONFIRM: {
            ESP_LOGI(TAG, "event: REGISTER_EVENT_IOTEX_USER_CONFIRM");

            ws_mqtt_set_status(WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_CONFIRM);

            break;
        }
    }
}

void iotex_register_device_event_user_confirm(void)
{
    ws_mqtt_set_status(WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_CONFIRM);
}

void ws_mqtt_token_server_request(void)
{

    char *message  = NULL;
    char *dev_sn = iotex_devinfo_dev_sn_get();
    if (NULL == dev_sn)
        return;

    cJSON *request = cJSON_CreateObject();

    cJSON_AddStringToObject(request, "project_name", WS_MQTT_TOKEN_SERVER_PROJECT_NAME);
    cJSON_AddStringToObject(request, "id", dev_sn);
    cJSON_AddStringToObject(request, "client_id", "seeed-001");

    message = cJSON_PrintUnformatted((const cJSON *)request);

    iotex_mqtt_pubscription(WS_MQTT_TOKEN_SERVER_TOPIC, message, strlen(message), 0);

    if (message)
        free(message);

    cJSON_Delete(request);
}

int iotex_mqtt_pubscription(unsigned char *topic, unsigned char *buf, unsigned int buflen, int qos)
{
    return esp_mqtt_client_publish(mqtt_client, (const char *)topic, (const char *)buf, buflen, 1, 0);
}

int iotex_mqtt_subscription(unsigned char *topic)
{
    return esp_mqtt_client_subscribe(mqtt_client, (const char *)topic, 0);
}

void ws_mqtt_app_server_start(void)
{

    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = app_mqtt_url,
    };

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);

    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    server_type = MQTT_SERVER_APP;
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, &server_type);
    esp_mqtt_client_start(mqtt_client);
}

static void __ws_mqtt_task(void *p_arg)
{
    uint8_t * eth_addr = NULL;

    xSemaphoreTake(__g_mqtt_task_sem, portMAX_DELAY);

    eth_addr = iotex_deviceconnect_sdk_core_get_eth_addr();
    iotex_eth_address_send(eth_addr, strlen(eth_addr));

    while (1) {
        ESP_LOGI(TAG, "MQTT status : %d", mqtt_status);

        switch (mqtt_status) {
            case WS_MQTT_STATUS_INIT:

                ws_mqtt_set_status(WS_MQTT_STATUS_DEV_SN_READY);    

                break;
            case WS_MQTT_STATUS_DEV_SN_READY:
                
                ws_mqtt_token_server_start();
                ws_mqtt_set_status(WS_MQTT_STATUS_TOKEN_SERVER_CONNECTING);

                break;                
            case WS_MQTT_STATUS_TOKEN_SERVER_SUBSCRIBED:
            case WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED:

                ws_mqtt_token_server_request();
                ws_mqtt_set_status(WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED);

                break;
            case WS_MQTT_STATUS_TOKEN_SERVER_RECEIVED:

                esp_mqtt_client_destroy(mqtt_client);
                ws_mqtt_set_status(WS_MQTT_STATUS_TOKEN_SERVER_FINISH);

                break;
            case WS_MQTT_STATUS_TOKEN_SERVER_FINISH:
            case WS_MQTT_STATUS_APP_SERVER_START:

                ws_mqtt_app_server_start();

                break;

            case WS_MQTT_STATUS_APP_SERVER_CONNECTED:

                iotex_mqtt_subscription(ws_mqtt_get_status_topic());

                break;

            case WS_MQTT_STATUS_APP_SERVER_STATUS_SUBSCRIBED:

                iotex_dev_access_query_dev_register_status(iotex_devinfo_mac_get(DEV_MAC_TYPE_HEX));

                break;
            case WS_MQTT_STATUS_APP_SERVER_BIND_STATUS_CONFIRM:

                iotex_dev_access_dev_register_confirm(iotex_devinfo_mac_get(DEV_MAC_TYPE_HEX));
                iotex_dev_access_query_dev_register_status(iotex_devinfo_mac_get(DEV_MAC_TYPE_HEX));

                break;
            default:

                break;
        }

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

static void __ip_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_id == IP_EVENT_STA_GOT_IP) {

        ESP_LOGI(TAG, "Got IP");

#ifdef WS_MQTT_HANDLE_USE_STATUS_MACHINE
        xSemaphoreGive(__g_mqtt_task_sem);
#endif

#ifdef WS_MQTT_HANDLE_USE_EVENT
        esp_event_post_to(mqtt_event_handle_t, MQTT_EVENT_BASE, WS_MQTT_STATUS_INIT, NULL, 0, portMAX_DELAY);
#endif
    }
}

#ifdef WS_MQTT_HANDLE_USE_EVENT
static void __mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data)
{

    ESP_LOGI(TAG, "MQTT Event : %d", id);
    switch (id) {

        case WS_MQTT_STATUS_INIT:

            ws_mqtt_token_server_start();
            break;
        case WS_MQTT_STATUS_TOKEN_SERVER_CONNECTING:
            break;
        case WS_MQTT_STATUS_TOKEN_SERVER_CONNECTED:

            iotex_mqtt_subscription("seeed-001");
            break;
        case WS_MQTT_STATUS_TOKEN_SERVER_SUBSCRIBED:

            ws_mqtt_token_server_request();
            break;
        case WS_MQTT_STATUS_TOKEN_SERVER_PUBLISHED:
            break;
        case WS_MQTT_STATUS_TOKEN_SERVER_RECEIVED:
            break;
        case WS_MQTT_STATUS_TOKEN_SERVER_FINISH:
            break;
        case WS_MQTT_STATUS_APP_SERVER_START:
            break;
        case WS_MQTT_STATUS_APP_SERVER_CONNECTED:
            break;
        case WS_MQTT_STATUS_APP_SERVER_RECONNECT:
            break;
        default:
            break;
    }
}
#endif

int iotex_ws_comm_init(void)
{
    __g_mqtt_task_sem   = xSemaphoreCreateBinary();
    __g_mqtt_status_sem = xSemaphoreCreateBinary();
    if (__g_mqtt_status_sem != NULL)
        xSemaphoreGive(__g_mqtt_status_sem);

    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &__ip_event_handler,
                                                        0,
                                                        NULL));

    ESP_ERROR_CHECK(esp_event_handler_instance_register_with(register_status_event_handle, 
                                                        REGISTER_STATUS_EVENT_BASE, REGISTER_STATUS_USER_CONFIRM, 
                                                        __register_event_handler, NULL, NULL));                                                        

#ifdef WS_MQTT_HANDLE_USE_EVENT
    esp_event_loop_args_t mqtt_event_task_args = {
        .queue_size      = 10,
        .task_name       = "mqtt_event_task",
        .task_priority   = uxTaskPriorityGet(NULL),
        .task_stack_size = 1024 * 4,
        .task_core_id    = tskNO_AFFINITY};

    ESP_ERROR_CHECK(esp_event_loop_create(&mqtt_event_task_args, &mqtt_event_handle_t));

    for (int i = 0; i < MQTT_EVENT_ALL; i++) {
        ESP_ERROR_CHECK(esp_event_handler_instance_register_with(mqtt_event_handle_t,
                                                                 MQTT_EVENT_BASE, i,
                                                                 __mqtt_event_handler, NULL, NULL));
    }
#endif

#ifdef WS_MQTT_HANDLE_USE_STATUS_MACHINE
    xTaskCreate(&__ws_mqtt_task, "__ws_mqtt_task", 1024 * 6, NULL, 10, NULL);
#endif
}
