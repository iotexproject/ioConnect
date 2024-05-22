#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_http_client.h"

#include "sprout_config.h"
#include "sprout.h"

#include "include/jose/jose.h"
#include "include/dids/dids.h"

static const char *TAG = "Sprout";

typedef struct UserData_t{
	char *data;
	int len;
}UserData_t;

static char messageID[SPROUT_MESSAGE_ID_SIZE]           = {0};
static char DIDToken[SPROUT_DID_TOKEN_SIZE]             = {0};
static char replyData[SPROUT_HTTP_REPLY_BUF_SIZE]       = {0};

static int _pal_sprout_http_response_parse(char *buf, int buf_len, int type, void *param) 
{
    if (NULL == buf || 0 == buf_len)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    if (SPROUT_HTTP_RESPONSE_DATA_TYPE_QUERY == type) {

        if (NULL == param)
            return IOTEX_SPROUT_ERR_BAD_INPUT_PARA; 

        char *msg_state = iotex_jwe_decrypt(buf, Ecdh1puA256kw, A256cbcHs512, NULL, NULL, (char *)param);
        if (msg_state)
            ESP_LOGI(TAG, "Receive Message State: %s\n", msg_state);
        else
            ESP_LOGE(TAG, "Failed to Decrypt\n");
    } 

    if (SPROUT_HTTP_RESPONSE_DATA_TYPE_SEND == type) {

        if (NULL == param)
            return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;        

        char *plain_text = iotex_jwe_decrypt(buf, Ecdh1puA256kw, A256cbcHs512, NULL, NULL, (char *)param);
        if (plain_text) {
            printf("Receive Message : %s\n", plain_text);

            cJSON *message_id_root = cJSON_Parse(plain_text);
            cJSON *message_id_item = cJSON_GetObjectItem(message_id_root, "messageID");

            memset(messageID, 0, SPROUT_MESSAGE_ID_SIZE);
            memcpy(messageID, message_id_item->valuestring, strlen(message_id_item->valuestring));

            free(plain_text);
        }
        else
            ESP_LOGE(TAG, "Failed to Decrypt");        
    }

    if (SPROUT_HTTP_RESPONSE_DATA_TYPE_JWT == type) {

        if (NULL == param)
            return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

        char *token = iotex_jwe_decrypt(buf, Ecdh1puA256kw, A256cbcHs512, NULL, NULL, (char *)param);
        if (token) {
            memset(DIDToken, 0, SPROUT_DID_TOKEN_SIZE);
            memcpy(DIDToken, "Bearer ", strlen("Bearer "));
            memcpy(DIDToken + strlen("Bearer "), token, strlen(token));

            free(token);

            ESP_LOGI(TAG, "Got Token : %s", DIDToken);
        } else 
            ESP_LOGE(TAG, "No Token");

    }

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

char *iotex_pal_sprout_send_message(char *message, char *ka_kid)
{
	esp_err_t err = ESP_OK;

    if (NULL == message || NULL == ka_kid)
        return NULL;

    if (0 == DIDToken[0])
        return NULL;
	
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
        .buffer_size_tx = 2560,
		.event_handler = http_handler,
		.user_data = (void*)&userData           
	};

	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_POST);
	// esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Authorization", DIDToken);
    esp_http_client_set_post_field(client, message, strlen(message));
    err = esp_http_client_perform(client);
    if(err == ESP_OK) {
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Http post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        _pal_sprout_http_response_parse(userData.data, userData.len, SPROUT_HTTP_RESPONSE_DATA_TYPE_SEND, ka_kid);
    } else
        return NULL;

    esp_http_client_cleanup(client);

    return messageID;
}

int iotex_pal_sprout_msg_query(char *ka_kid)
{
	esp_err_t err = ESP_OK;
    char path[128] = {0};

    if (NULL == ka_kid)
        return NULL;
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};

    memcpy(path, "/message/", strlen("/message/"));    
    memcpy(path + strlen("/message/"), messageID, strlen(messageID));   

    ESP_LOGI(TAG, "GET[%d] : %s", strlen(path), path); 
	
	esp_http_client_config_t config = {
        .host = IOTEX_SPROUT_HTTP_HOST,
        .port = IOTEX_SPROUT_HTTP_PORT,
        .path = path,
		.keep_alive_enable = 0,
        .buffer_size_tx = 2560,
		.timeout_ms = IOTEX_SPROUT_HTTP_TIMEOUT,
		.event_handler = http_handler,
		.user_data = (void*)&userData
	};

	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_GET);
    esp_http_client_set_header(client, "Authorization", DIDToken);
    err = esp_http_client_perform(client);
    if(err == ESP_OK){
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Https post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        _pal_sprout_http_response_parse(userData.data, userData.len, SPROUT_HTTP_RESPONSE_DATA_TYPE_QUERY, ka_kid);
    }	

    esp_http_client_cleanup(client);    

    return err;
}

int iotex_pal_sprout_request_token(char *did, char *ka_kid)
{
	esp_err_t err = ESP_OK;

    if (NULL == did || NULL == ka_kid)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;
	
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};
	
	esp_http_client_config_t config = {
        .host = IOTEX_SPROUT_HTTP_HOST,
        .port = IOTEX_SPROUT_HTTP_PORT,
        .path = IOTEX_SPROUT_HTTP_PATH_REQUEST_TOKEN,
		.keep_alive_enable = 0,
		.timeout_ms = IOTEX_SPROUT_HTTP_TIMEOUT,
        .buffer_size_tx = 256,
		.event_handler = http_handler,
		.user_data = (void*)&userData           
	};
	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_POST);
	// esp_http_client_set_header(client, "Content-Type", "application/json");

    cJSON * client_id = cJSON_CreateObject();
    if (NULL == client_id)
        return IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY;

    cJSON_AddStringToObject(client_id, "clientID", did);

    char *client_id_serialize = cJSON_PrintUnformatted(client_id);
    if (NULL == client_id_serialize)
        goto exit;

    esp_http_client_set_post_field(client, client_id_serialize, strlen(client_id_serialize));
    
    err = esp_http_client_perform(client);
    if(err == ESP_OK){
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Http post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        _pal_sprout_http_response_parse(userData.data, userData.len, SPROUT_HTTP_RESPONSE_DATA_TYPE_JWT, ka_kid);

        memset(replyData, 0, sizeof(replyData));
    }	

exit:
    free(client_id_serialize);

    cJSON_Delete(client_id);

    esp_http_client_cleanup(client);

    return err;
}

DIDDoc *iotex_pal_sprout_server_diddoc_get(void)
{
    DIDDoc *diddoc_parse = NULL;
	
	esp_err_t err = ESP_OK;
	UserData_t userData = {
		.data = replyData,
		.len = 0,
	};
	
	esp_http_client_config_t config = {
        .host = IOTEX_SPROUT_HTTP_HOST,
        .port = IOTEX_SPROUT_HTTP_PORT,
        .path = IOTEX_SPROUT_HTTP_PATH_GET_DIDDOC,
		.keep_alive_enable = 0,
		.timeout_ms = IOTEX_SPROUT_HTTP_TIMEOUT,
        .buffer_size_tx = 128,
		.event_handler = http_handler,
		.user_data = (void*)&userData           
	};
	esp_http_client_handle_t client = esp_http_client_init(&config);
	esp_http_client_set_method(client, HTTP_METHOD_GET);
	
    err = esp_http_client_perform(client);
    if(err == ESP_OK){
    	int statusCode = esp_http_client_get_status_code(client);
    	ESP_LOGI(TAG, "Http post status = %d\n", statusCode);
    	ESP_LOGI(TAG, "sever data = %s  sever data len=%d\n", userData.data, userData.len );

        diddoc_parse = iotex_diddoc_parse(userData.data);
        if (NULL == diddoc_parse) {
            ESP_LOGE(TAG, "Failed to DIDDoc Parse\n");          
            goto exit;
        }

        unsigned int vm_num = iotex_diddoc_verification_method_get_num(diddoc_parse, VM_PURPOSE_KEY_AGREEMENT);
        if (0 == vm_num)
            goto exit;

        VerificationMethod_Info *vm_info = iotex_diddoc_verification_method_get(diddoc_parse, VM_PURPOSE_KEY_AGREEMENT, vm_num - 1);             
        if (NULL == vm_info) {
            ESP_LOGE(TAG, "Failed to get VerificationMethod_Info\n");
            goto exit;
        }

        if (vm_info->pubkey_type == VERIFICATION_METHOD_PUBLIC_KEY_TYPE_JWK)
            iotex_registry_item_register(vm_info->id, vm_info->pk_u.jwk);    
    }	

exit:
    memset(replyData, 0, sizeof(replyData));
    
    esp_http_client_cleanup(client);

    return diddoc_parse;
}
