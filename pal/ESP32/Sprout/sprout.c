#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_http_client.h"

#include "sprout_config.h"
#include "sprout.h"

static const char *TAG = "Sprout";

typedef struct UserData_t{
	char *data;
	int len;
}UserData_t;

static char messageID[SPROUT_MESSAGE_ID_SIZE] = {0};
static char DIDToken[SPROUT_DID_TOKEN_SIZE] = {0};
static char query_path[SPROUT_QUERY_PATH_SIZE] = {0};
static char replyData[SPROUT_HTTP_REPLY_BUF_SIZE] = {0};
static int  replyLen = 0;

static int sprout_http_response_parse(char *buf, int buf_len, int type) 
{
    cJSON *json           = NULL;
    cJSON *json_payload   = NULL;

    if (NULL == buf || 0 == buf_len)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    json = cJSON_Parse(buf);
    if (NULL == json)
        return IOTEX_SPROUT_ERR_DATA_FORMAT;    

    if (SPROUT_HTTP_DATA_TYPE_SEND == type) {
        json_payload = cJSON_GetObjectItem(json, "messageID");
        if (json_payload == NULL || !cJSON_IsString(json_payload)) {
            ESP_LOGI(TAG, "MessageID : Error");
            return IOTEX_SPROUT_ERR_DATA_FORMAT;
        }

        memset(messageID, 0, SPROUT_MESSAGE_ID_SIZE);
        memcpy(messageID, json_payload->valuestring, strlen(json_payload->valuestring));
    }

#if (IOTEX_SPROUT_COMMUNICATE_TYPE == SPROUT_COMMUNICATE_TYPE_DID)
    if (SPROUT_HTTP_DATA_TYPE_JWT == type) {
        json_payload = cJSON_GetObjectItem(json, "verifiableCredential");
        if (json_payload == NULL || !cJSON_IsString(json_payload)) {
            ESP_LOGI(TAG, "verifiableCredential : Error");
            return IOTEX_SPROUT_ERR_DATA_FORMAT;
        }

        memset(DIDToken, 0, SPROUT_DID_TOKEN_SIZE);
        memcpy(DIDToken, json_payload->valuestring, strlen(json_payload->valuestring));

        DIDToken[strlen(json_payload->valuestring) - 1] = DIDToken[strlen(json_payload->valuestring) - 1] + 1;
    }
#endif

    return IOTEX_SPROUT_ERR_SUCCESS;
}

static esp_err_t http_handler(esp_http_client_event_t *evt)
{
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            if(evt->user_data){
            	UserData_t* userData = (UserData_t*)evt->user_data;
                ESP_LOGI(TAG, "userData[%d], evt[%d]", userData->len, evt->data_len);
                if ((userData->len + evt->data_len) >= SPROUT_HTTP_REPLY_BUF_SIZE)
                    return ESP_OK;
            	memcpy(userData->data + userData->len, evt->data, evt->data_len);
            	userData->len += evt->data_len;
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        default:
        	break;
    }
    return ESP_OK;
}

char *iotex_sprout_http_send_message(char *post_field, int post_field_len)
{
	esp_err_t err = ESP_OK;
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};

	esp_http_client_config_t config = {
        .host = IOTEX_SPROUT_HTTP_HOST,
        .port = IOTEX_SPROUT_HTTP_PORT,
        .path = IOTEX_SPROUT_HTTP_PATH_MESSAGE,
		.keep_alive_enable = 0,
		.timeout_ms = IOTEX_SPROUT_HTTP_TIMEOUT,
		.event_handler = http_handler,
		.user_data = (void*)&userData           
	};

	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_POST);
	esp_http_client_set_header(client, "Content-Type", "application/json");

#if (IOTEX_SPROUT_COMMUNICATE_TYPE == SPROUT_COMMUNICATE_TYPE_DID)
    esp_http_client_set_header(client, "Authorization", DIDToken);
#endif

    esp_http_client_set_post_field(client, post_field, post_field_len);

    err = esp_http_client_perform(client);
    if(err == ESP_OK) {
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Http post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        sprout_http_response_parse(userData.data, userData.len, SPROUT_HTTP_DATA_TYPE_SEND);
    } else {
        return NULL;
    }	 

    esp_http_client_cleanup(client);

    return messageID;
}

int iotex_device_connect_pal_sprout_http_query(char *message_id, int message_id_len)
{
	esp_err_t err = ESP_OK;
    char path[128] = {0};
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};

    memcpy(path, "/message/", strlen("/message/"));    
    memcpy(path + strlen("/message/"), message_id, message_id_len);   

    ESP_LOGI(TAG, "GET[%d] : %s", strlen(path), path); 
	
	esp_http_client_config_t config = {
        .host = IOTEX_SPROUT_HTTP_HOST,
        .port = IOTEX_SPROUT_HTTP_PORT,
        .path = path,
		.keep_alive_enable = 0,
		.timeout_ms = IOTEX_SPROUT_HTTP_TIMEOUT,
		.event_handler = http_handler,
		.user_data = (void*)&userData
	};

	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_GET);
    err = esp_http_client_perform(client);
    if(err == ESP_OK){
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Https post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );
    }	

    esp_http_client_cleanup(client);    

    return err;
}

#if (IOTEX_SPROUT_COMMUNICATE_TYPE == SPROUT_COMMUNICATE_TYPE_DID)
int iotex_sprout_did_http_get_jwt(char *vc, uint32_t vc_len)
{
	esp_err_t err = ESP_OK;

    if (vc == NULL || vc_len == 0)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};
	
	esp_http_client_config_t config = {
        .host = IOTEX_SPROUT_HTTP_HOST,
        .port = IOTEX_SPROUT_HTTP_PORT,
        .path = IOTEX_SPROUT_HTTP_PATH_CREDENTIAL,
		.keep_alive_enable = 0,
		.timeout_ms = IOTEX_SPROUT_HTTP_TIMEOUT,
        .buffer_size_tx = 2048,
		.event_handler = http_handler,
		.user_data = (void*)&userData           
	};
	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_POST);
	esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_http_client_set_post_field(client, vc, vc_len);
    
    err = esp_http_client_perform(client);
    if(err == ESP_OK){
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Http post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        sprout_http_response_parse(userData.data, userData.len, SPROUT_HTTP_DATA_TYPE_JWT);

        memset(replyData, 0, sizeof(replyData));
    }	

    esp_http_client_cleanup(client);

    return err;
}
#endif

char *iotex_sprout_project_query_path_get(void)
{
    char *p_query_path = query_path;

    if (!messageID[0])
        return NULL;

    memset(query_path, 0, SPROUT_QUERY_PATH_SIZE);
    memcpy(p_query_path, "/message/", strlen("/message/"));    
    p_query_path += strlen("/message/");
    memcpy(p_query_path, messageID, strlen(messageID));   

    ESP_LOGI(TAG, "GET[%d] : %s", strlen(query_path), query_path); 

    return query_path;
}
