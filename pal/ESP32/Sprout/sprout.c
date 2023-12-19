#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_http_client.h"

#include "sprout_config.h"
#include "sprout.h"

static const char *TAG = "Sprout";

#define SPROUT_HTTP_DATA_TYPE_SEND          1

typedef struct UserData_t{
	char *data;
	int len;
}UserData_t;

char url[256] = "sprout-staging.w3bstream.com:9000/message"; 
char replyData[10240] = {0};
int  replyLen = 0;

static char messageID[256] = {0};

static int sprout_http_data_parse(char *buf, int buf_len, int type) 
{
    cJSON *json           = NULL;
    cJSON *json_payload   = NULL;

    if (NULL == buf || 0 == buf_len)
        return -1;

    json = cJSON_Parse(buf);
    if (NULL == json)
        return -2;    

    if (SPROUT_HTTP_DATA_TYPE_SEND == type) {
        json_payload = cJSON_GetObjectItem(json, "messageID");
        if (json_payload == NULL || !cJSON_IsString(json_payload)) {
            ESP_LOGI(TAG, "MessageID : Error");
            return -3;
        }

        ESP_LOGI(TAG, "MessageID : %s", json_payload->valuestring);
        memset(messageID, 0, 256);
        memcpy(messageID, json_payload->valuestring, strlen(json_payload->valuestring));
    }

    return 0;
}

static char *sprout_text_send_message(void) 
{
    char *message  = NULL;

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddNumberToObject(payload, "projectID", 10001);
    cJSON_AddStringToObject(payload, "projectVersion", "0.1");
    cJSON_AddStringToObject(payload, "data", "{\"private_a\": 3, \"private_b\": 4}");

    message = cJSON_PrintUnformatted((const cJSON *)payload);

    ESP_LOGI(TAG, "POST[%d] : %s", strlen(message), message);

    return message;
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
                if ((userData->len + evt->data_len) >= 10240)
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

char *iotex_device_connect_pal_sprout_http_send_message(char *post_field, int post_field_len)
{
	esp_err_t err = ESP_OK;
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};

	esp_http_client_config_t config = {
        .host = IOTEX_SPROUT_HOST,
        .port = IOTEX_SPROUT_PORT,
        .path = IOTEX_SPROUT_PATH,
		.keep_alive_enable = 0,
		.timeout_ms = 3000,
		.event_handler = http_handler,
		.user_data = (void*)&userData           
	};

	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_POST);
	esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_http_client_set_post_field(client, post_field, post_field_len);

    err = esp_http_client_perform(client);
    if(err == ESP_OK) {
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Http post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        sprout_http_data_parse(userData.data, userData.len, SPROUT_HTTP_DATA_TYPE_SEND);
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
        .host = IOTEX_SPROUT_HOST,
        .port = IOTEX_SPROUT_PORT,
        .path = path,
		.keep_alive_enable = 0,
		.timeout_ms = 5000,
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

int http_post()
{
    char *post_field = NULL;

	esp_err_t err = ESP_OK;
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};
	
	esp_http_client_config_t config = {
        .host = "sprout-staging.w3bstream.com",
        .port = 9000,
        .path = "/message",
		.keep_alive_enable = 0,
		.timeout_ms = 3000,
		.event_handler = http_handler,
		.user_data = (void*)&userData           
	};
	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_POST);
	esp_http_client_set_header(client, "Content-Type", "application/json");

    post_field = sprout_text_send_message();

    esp_http_client_set_post_field(client, post_field, strlen(post_field));//设置报文主体
    

    err = esp_http_client_perform(client);
    if(err == ESP_OK){
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Http post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        sprout_http_data_parse(userData.data, userData.len, SPROUT_HTTP_DATA_TYPE_SEND);
    }	

    esp_http_client_cleanup(client);

    return err;
}

char query_path[128] = {0};

static char *sprout_get_query_path(void)
{
    char *p_query_path = query_path;

    if (!messageID[0])
        return NULL;

    memset(query_path, 0, 128);
    memcpy(p_query_path, "/message/", strlen("/message/"));    
    p_query_path += strlen("/message/");
    memcpy(p_query_path, messageID, strlen(messageID));   

    ESP_LOGI(TAG, "GET[%d] : %s", strlen(query_path), query_path); 

    return query_path;
}

int http_get()
{
	esp_err_t err = ESP_OK;
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};
	
	esp_http_client_config_t config = {
		// .url = url,
        .host = "sprout-staging.w3bstream.com",
        .port = 9000,
        .path = sprout_get_query_path(),
		.keep_alive_enable = 0,
		.timeout_ms = 5000,
		.event_handler = http_handler,
		.user_data = (void*)&userData
	};
	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_GET);
    err = esp_http_client_perform(client);
    if(err == ESP_OK){
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Https post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );//打印服务器回复内容
    }	

    esp_http_client_cleanup(client);    

    return err;
}



