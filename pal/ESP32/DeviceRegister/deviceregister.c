#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"

#include "esp_console.h"
#include "esp_log.h"

#if (IOTEX_PAL_DEVICE_REGISTER_MODE == IOTEX_PAL_DEVICE_REGISTER_MODE_HTTPS)
#include "esp_https_server.h"
#endif

#include "include/jose/jose.h"
#include "include/dids/dids.h"

#include "deviceregister.h"

static const char *TAG = "DevReg";

/** @brief Return larger value of two provided expressions.
 *
 * @note Arguments are evaluated twice. See Z_MAX for GCC only, single
 * evaluation version.
 */
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/** @brief Return smaller value of two provided expressions.
 *
 * @note Arguments are evaluated twice. See Z_MIN for GCC only, single
 * evaluation version.
 */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN  (64)

static TaskHandle_t pxCreatedTask;
static esp_log_level_t log_level = 0;

static httpd_handle_t server = NULL;

static char * upload_did = NULL;
static char * upload_diddoc = NULL;

static char str2Hex(char c) {

    if (c >= '0' && c <= '9') {
        return (c - '0');
    }

    if (c >= 'a' && c <= 'z') {
        return (c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'Z') {
        return (c -'A' + 10);
    }

    return c;
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

static int hexStr2Bin(char *str, char *bin) {
	
    int i,j;
    for(i = 0,j = 0; j < (strlen(str)>>1) ; i++,j++) {
        bin[j] = (str2Hex(str[i]) <<4);
        i++;
        bin[j] |= str2Hex(str[i]);
    }

    return j; 
}

char * iotex_pal_device_register_did_upload_prepare(char *did, uint32_t keyid)
{
    char *did_serialize = NULL;

    uint8_t signature[64];
    char signature_str[64 * 2 + 1] = {0};

    uint8_t puk[64] = {0};
    char puk_str[64 * 2 + 4 + 1] = {0};

    size_t puk_length = 0;

    puk_str[0] = '0';
    puk_str[1] = 'x';
    puk_str[2] = '0';
    puk_str[3] = '4';

    if (NULL == did)
        return NULL;

    if (0 == keyid)
        keyid = 1;

    cJSON *did_root = cJSON_CreateObject();
    if (NULL == did_root)
        return NULL;

    cJSON_AddStringToObject(did_root, "did", did);

    psa_status_t status = psa_export_public_key( keyid, (uint8_t *)puk, sizeof(puk), &puk_length );
    if (PSA_SUCCESS != status)
        goto exit;

    hex2str(puk, puk_length, puk_str + 4);

    cJSON_AddStringToObject(did_root, "puk", puk_str);

    uint8_t hash[32];
    size_t  hash_size = 0;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    
    psa_hash_setup(&operation, PSA_ALG_SHA_256);
    psa_hash_update(&operation, did, strlen(did));
    psa_hash_update(&operation, puk_str, strlen(puk_str));
    psa_hash_finish(&operation, hash, sizeof(hash), &hash_size);
    
    size_t  signature_length;
    status = psa_sign_hash(keyid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_size, signature, sizeof(signature), &signature_length);
    if (PSA_SUCCESS != status)
        goto exit;

    hex2str(signature, signature_length, signature_str);        

    cJSON_AddStringToObject(did_root, "signature", signature_str);

    did_serialize = cJSON_Print(did_root);

exit:
    cJSON_Delete(did_root);

    return did_serialize;    
}

char * iotex_pal_device_register_diddoc_upload_prepare(char *diddoc, uint32_t keyid)
{
    char *diddoc_serialize = NULL;

    uint8_t signature[64];
    char signature_str[64 * 2 + 1] = {0};

    if (NULL == diddoc)
        return NULL;

    if (0 == keyid)
        keyid = 1;

    cJSON *diddoc_root = cJSON_CreateObject();
    if (NULL == diddoc_root)
        return NULL;

    cJSON *diddoc_item = cJSON_Parse(diddoc);
    if (NULL == diddoc_item)
        goto exit;

    cJSON_AddItemToObject(diddoc_root, "diddoc", diddoc_item);

    size_t signature_length = 0;
    psa_status_t status =  psa_sign_message(keyid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), diddoc, strlen(diddoc), signature, 64, &signature_length);
    if (status != PSA_SUCCESS)
        goto exit;

    hex2str(signature, signature_length, signature_str);

    cJSON_AddStringToObject(diddoc_root, "signature", signature_str);

    diddoc_serialize = cJSON_Print(diddoc_root);
exit:
    cJSON_Delete(diddoc_root);

    return diddoc_serialize;
}

char * iotex_pal_device_register_signature_response_prepare(char *buf, uint32_t keyid)
{
    char *sign_serialize = NULL;
    char signature_str[64 * 2 + 2 + 1] = {0};
    uint8_t hexbin[128] = {0};

    if (NULL == buf)
        return NULL;

    if (0 == keyid)
        keyid = 1;
    
    cJSON *hex_root = cJSON_Parse(buf);
    if (NULL == hex_root)
        return NULL;
    
    cJSON *hex_item = cJSON_GetObjectItem(hex_root, "hex");
    if (NULL == hex_item || !cJSON_IsString(hex_item))
        goto exit;

    char *hex_str = hex_item->valuestring;
    if(hex_str[0] != '0' || hex_str[1] != 'x')
        goto exit;

    int hexbin_len = hexStr2Bin(hex_str + 2, hexbin);
    
    uint8_t signature[64];
    size_t  signature_length;
    psa_status_t status = psa_sign_hash(keyid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hexbin, hexbin_len, signature, sizeof(signature), &signature_length);
    if (PSA_SUCCESS != status)
        goto exit;

    signature_str[0] = '0';
    signature_str[1] = 'x';

    hex2str(signature, signature_length, signature_str + 2);        
    
    cJSON *sign = cJSON_CreateObject();
    if (NULL == sign)
        goto exit;

    cJSON_AddStringToObject(sign, "sign", signature_str);

    sign_serialize = cJSON_Print(sign);

    cJSON_Delete(sign);

exit:
    cJSON_Delete(hex_root); 

    return sign_serialize;
}

#if (IOTEX_PAL_DEVICE_REGISTER_MODE == IOTEX_PAL_DEVICE_REGISTER_MODE_HTTPS)
static esp_err_t did_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    httpd_resp_set_type(req, "application/json");

    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "*");    
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "*");    

    httpd_resp_send(req, upload_did, HTTPD_RESP_USE_STRLEN);

#if 0
    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
#endif

    return ESP_OK;
}

static esp_err_t diddoc_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    httpd_resp_set_type(req, "application/json");

    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "*");    
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "*");      

    httpd_resp_send(req, upload_diddoc, HTTPD_RESP_USE_STRLEN);
#if 0
    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
#endif

    return ESP_OK;
}

static esp_err_t sign_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;
    ESP_LOGI(TAG, "Receive Post Content Len %d", remaining);

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                        MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        // httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        // ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        // ESP_LOGI(TAG, "%.*s", ret, buf);
        // ESP_LOGI(TAG, "====================================");
    }

    char *sign = iotex_pal_device_register_signature_response_prepare(buf, 1);
    if (sign)
        printf("%s\n", sign);
    else
        printf("No Sign\n");   

    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "*");         

    httpd_resp_send(req, sign, HTTPD_RESP_USE_STRLEN);

    // End response
    // httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

esp_err_t cors_handler(httpd_req_t *req) {
    
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "*");
    
    if (req->method == HTTP_OPTIONS) 
        httpd_resp_send(req, NULL, 0);

    return ESP_OK;
}

esp_err_t options_handler(httpd_req_t *req) {
    
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "*");
    
    httpd_resp_set_status(req, "204");
    httpd_resp_send(req, NULL, 0); 

    return ESP_OK;
}

static const httpd_uri_t did = {
    .uri       = "/did",
    .method    = HTTP_GET,
    .handler   = did_get_handler,
};

static const httpd_uri_t did_options = {
    .uri       = "/did",
    .method    = HTTP_OPTIONS,
    .handler   = options_handler,
};

static const httpd_uri_t diddoc = {
    .uri       = "/diddoc",
    .method    = HTTP_GET,
    .handler   = diddoc_get_handler,
};

static const httpd_uri_t diddoc_options = {
    .uri       = "/diddoc",
    .method    = HTTP_OPTIONS,
    .handler   = options_handler,
};

static const httpd_uri_t sign = {
    .uri       = "/sign",
    .method    = HTTP_POST,
    .handler   = sign_post_handler,
};

static const httpd_uri_t sign_options = {
    .uri       = "/sign",
    .method    = HTTP_OPTIONS,
    .handler   = options_handler,
};

static const httpd_uri_t uri_options = {
    .uri       = "/*",
    .method    = HTTP_OPTIONS,
    .handler   = cors_handler,
};

static void _pal_sprout_webserver_secure_start(void)
{
    ESP_LOGI(TAG, "Starting server");

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.port_secure  = 8000;

    extern const unsigned char servercert_start[] asm("_binary_servercert_pem_start");
    extern const unsigned char servercert_end[]   asm("_binary_servercert_pem_end");
    conf.servercert = servercert_start;
    conf.servercert_len = servercert_end - servercert_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    conf.prvtkey_pem = prvtkey_pem_start;
    conf.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;

#if CONFIG_EXAMPLE_ENABLE_HTTPS_USER_CALLBACK
    conf.user_cb = https_server_user_callback;
#endif
    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret) {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }

    ESP_LOGI(TAG, "Registering URI handlers");
    httpd_register_uri_handler(server, &uri_options);
    httpd_register_uri_handler(server, &did);
    httpd_register_uri_handler(server, &did_options);
    httpd_register_uri_handler(server, &diddoc);
    httpd_register_uri_handler(server, &diddoc_options);
    httpd_register_uri_handler(server, &sign);    
    httpd_register_uri_handler(server, &sign_options);

}
#endif

#if (IOTEX_PAL_DEVICE_REGISTER_MODE == IOTEX_PAL_DEVICE_REGISTER_MODE_SERIAL)
static void _sprout_device_register_serial_task(void *p_arg)
{
    char buffer[128] = {0};

    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
    };

    // Configure UART parameters
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_config));
    uart_set_pin(UART_NUM_0, -1, -1, -1, -1);
    uart_driver_install(UART_NUM_0, 256, 0, 0, NULL, 0);

    log_level = esp_log_level_get("*");

    esp_log_level_set("*", ESP_LOG_NONE);    

    while(1) {

        int len = uart_read_bytes(UART_NUM_0, buffer, 128, 20 / portTICK_PERIOD_MS);   
        
        if (len == 6)
            uart_write_bytes(UART_NUM_0, (const char *) upload_did, strlen(upload_did));    
        else if (len == 9)
            uart_write_bytes(UART_NUM_0, (const char *) upload_diddoc, strlen(upload_diddoc));
        else if (buffer[0] == 'S') {
            char *sign = iotex_pal_device_register_signature_response_prepare(buffer + 1, 1);
            if (sign)
                uart_write_bytes(UART_NUM_0, (const char *) sign, strlen(sign));
            else
                uart_write_bytes(UART_NUM_0, (const char *) "Signature Err", strlen("Signature Err"));
        } 

        if (buffer[0])
            memset(buffer, 0, 128);        

    }

    vTaskDelete(NULL);
}
#endif

static void _pal_sprout_upload_init(void)
{
    if (upload_did)
        free(upload_did);

    if (upload_diddoc)
        free(upload_diddoc);
}

void iotex_pal_sprout_device_register_start(char *did, char *diddoc)
{
    if (NULL == did || NULL == diddoc)
        return;

    _pal_sprout_upload_init();

    upload_did    = iotex_pal_device_register_did_upload_prepare(did, 1);
    upload_diddoc = iotex_pal_device_register_diddoc_upload_prepare(diddoc, 1);

#if (IOTEX_PAL_DEVICE_REGISTER_MODE == IOTEX_PAL_DEVICE_REGISTER_MODE_SERIAL)
        xTaskCreate(_sprout_device_register_serial_task, "device_register_task", 1024 * 5, NULL, 10, &pxCreatedTask);
#elif (IOTEX_PAL_DEVICE_REGISTER_MODE == IOTEX_PAL_DEVICE_REGISTER_MODE_HTTPS)
        _pal_sprout_webserver_secure_start();
#endif        

}

void iotex_pal_sprout_device_register_stop(void)
{
    _pal_sprout_upload_init();
    
    if (NULL == pxCreatedTask)
        goto mode_https;

    esp_log_level_set("*", log_level);
    uart_driver_delete(UART_NUM_0);
    vTaskDelete(pxCreatedTask);

    pxCreatedTask = NULL;

mode_https:

    if (server)
        httpd_ssl_stop(server);
}



