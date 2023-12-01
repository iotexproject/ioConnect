#include "upload_data.h"
#include "DeviceConnect_Core.h"
#include "device_connect_config.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_wifi.h"

static const char *TAG           = "device_connect";

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER_TEST
ESP_EVENT_DEFINE_BASE(SENSOR_DATA_EVENT_BASE);
esp_event_loop_handle_t sensor_data_event_handle;
#endif

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER
ESP_EVENT_DEFINE_BASE(REGISTER_STATUS_EVENT_BASE);
esp_event_loop_handle_t register_status_event_handle;

ESP_EVENT_DEFINE_BASE(WS_PARA_EVENT_BASE);
esp_event_loop_handle_t ws_para_event_handle;
#endif

struct dev_mac dev_mac_t;
static int status_now = -1;
static char device_sn[IOTEX_DEVICE_SN_LEN] = {0};
static char wallet_address[64] = {0};
static char eth_address[32] = {0};

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

static void iotex_dev_mac_init(void)
{
    memset(&dev_mac_t, 0, sizeof(struct dev_mac));
    esp_read_mac(dev_mac_t.mac, ESP_MAC_WIFI_STA);

    dev_mac_t.mac[5] += UPLOAD_DATA_TEST_DEV_MAC_OFFSET;

    hex2str(dev_mac_t.mac, 6, dev_mac_t.mac_str);
    dev_mac_t.valid = 1;
}

char *iotex_devinfo_mac_get(enum dev_mac_type mac_type)
{

    int8_t *mac_addr = NULL;

    if (0 == dev_mac_t.valid)
        return NULL;

    switch (mac_type) {
        case DEV_MAC_TYPE_HEX:
            mac_addr = dev_mac_t.mac;
            break;
        case DEV_MAC_TYPE_STR:
            mac_addr = dev_mac_t.mac_str;
            break;
        default:
            mac_addr = NULL;
            break;
    }

    return mac_addr;
}

static void iotex_dev_status_handle(int iotex_status)
{
    switch (iotex_status)
    {
    case 0:
        esp_event_post_to(register_status_event_handle, REGISTER_STATUS_EVENT_BASE, REGISTER_STATUS_DEVICE_SHOULD_ENROLL, NULL, NULL, portMAX_DELAY);
        break;
    case 1:        
        esp_event_post_to(register_status_event_handle, REGISTER_STATUS_EVENT_BASE, REGISTER_STATUS_DEVICE_CONFIRM_NEEDED, NULL, NULL, portMAX_DELAY);
        break;    
    case 2:        
        esp_event_post_to(register_status_event_handle, REGISTER_STATUS_EVENT_BASE, REGISTER_STATUS_DEVICE_SUCCESS, NULL, NULL, portMAX_DELAY);
        break;           
    default:
        break;
    }
}

void iotex_upload_data_set_status(int status)
{
    if (status > status_now) {

        status_now = status;

        iotex_dev_status_handle(status_now);

    }
}

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER_TEST
static void __upload_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data)
{
    cJSON *user_data = cJSON_CreateObject();
    cJSON_AddNumberToObject(user_data, "sensor_type", *(int *)event_data);  

    iotex_dev_access_data_upload_with_userdata(user_data, 1, IOTEX_USER_DATA_TYPE_JSON, iotex_devinfo_mac_get(DEV_MAC_TYPE_HEX));  

    cJSON_Delete(user_data);
}
#endif

void iotex_wallet_address_send(char *buf, int buf_len) 
{
    if ( buf == NULL || buf_len == 0)
        return;

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER
    esp_event_post_to(ws_para_event_handle, WS_PARA_EVENT_BASE, WS_PARA_WALLET_ADDRESS, buf, buf_len, portMAX_DELAY);
#else
    memset(wallet_address, 0, 64);
#endif    
}

char *iotex_wallet_address_get(void) 
{
    if (wallet_address[0])
        return wallet_address;

    return NULL;
}

void iotex_eth_address_send(char *buf, int buf_len) 
{
    if ( buf == NULL || buf_len == 0)
        return;

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER
    esp_event_post_to(ws_para_event_handle, WS_PARA_EVENT_BASE, WS_PARA_ETH_ADDRESS, buf, buf_len, portMAX_DELAY);
#else
    memset(eth_address, 0, 32);
#endif    
}

char *iotex_eth_address_get(void) 
{
    if (eth_address[0])
        return eth_address;

    return NULL;
}

int iotex_devinfo_query_dev_sn(void)
{
#ifdef IOTEX_DEVICE_SN_USE_STATIC
    memset(device_sn, 0, IOTEX_DEVICE_SN_LEN);
    memcpy(device_sn, IOTEX_DEVICE_SN, strlen(IOTEX_DEVICE_SN));
#endif 
}

char *iotex_devinfo_dev_sn_get(void)
{
    if(device_sn[0])
        return device_sn;

    return NULL;
}

void iotex_upload_data_init(void)
{
#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER
    esp_event_loop_args_t register_status_loop_args = {
        .queue_size      = 10,
        .task_name       = "register_status",
        .task_priority   = uxTaskPriorityGet(NULL),
        .task_stack_size = 5120,
        .task_core_id    = tskNO_AFFINITY,
    };

    ESP_ERROR_CHECK(esp_event_loop_create(&register_status_loop_args, &register_status_event_handle));      

    esp_event_loop_args_t ws_para_loop_args = {
        .queue_size      = 10,
        .task_name       = "ws_para",
        .task_priority   = uxTaskPriorityGet(NULL),
        .task_stack_size = 5120,
        .task_core_id    = tskNO_AFFINITY,
    };

    ESP_ERROR_CHECK(esp_event_loop_create(&ws_para_loop_args, &ws_para_event_handle));         
#endif

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER_TEST
    ESP_ERROR_CHECK(esp_event_handler_instance_register_with(STANDARD_LAYER_EVENT_LOOP,
                                                             STANDARD_LAYER_EVENT_BASE, STANDARD_LAYER_EVENT_ID,
                                                             __upload_event_handler, NULL, NULL));                                                         
#endif                                                             

    iotex_dev_mac_init();

}