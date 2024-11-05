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

#include "include/utils/convert/convert.h"
#include "include/utils/devRegister/devRegister.h"

static const char *TAG = "DevReg";

static char * upload_did = NULL;
static char * upload_diddoc = NULL;

static uint8_t secret[32] = {0x57, 0x81, 0x5e, 0x3d, 0x20, 0x9a, 0x42, 0x8d, 0x48, 0x44, 0x83, 0xcc, 0x1a, 0x2c, 0x5b, 0x5d, 0x97, 0x00, 0x7d, 0x5f, 0x17, 0xff, 0xc0, 0xd4, 0xee, 0xd6, 0x03, 0xa4, 0x08, 0x55, 0x03, 0x9e};

static psa_key_id_t device_register_key_id = 0;
static uint8_t signature[64] = {0};
static char    signature_str[64 * 2 + 1] = {0};

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

    char *sign = iotex_utils_device_register_signature_response_prepare(buf, 1);
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
    char *sign = NULL;
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
        if (0 == len)
            continue;           

        if (0 == strncmp("getdiddoc", buffer, 9)) {
            uart_write_bytes(UART_NUM_0, (const char *) upload_diddoc, strlen(upload_diddoc));
        } else if (0 == strncmp("getdid", buffer, 6)) {
            uart_write_bytes(UART_NUM_0, (const char *) upload_did, strlen(upload_did)); 
        } else if (0 == strcmp("quit", buffer)) {
            goto exit;
        } else {
            char *sign = iotex_utils_device_register_signature_response_prepare(buffer, 1);
            if (sign) {
                uart_write_bytes(UART_NUM_0, (const char *) sign, strlen(sign));
            } else {
                uart_write_bytes(UART_NUM_0, (const char *) "{\n\t\"Sign\":\t\"Failed to Signature\"\n}", strlen("{\n\t\"Sign\":\t\"Failed to Signature\"\n}"));    
            }

            if (sign) {
                free(sign);
                sign = NULL;
            }
        }

        if (buffer[0])
            memset(buffer, 0, 128);          

        vTaskDelay(pdMS_TO_TICKS(200));
    }

exit:
    vTaskDelete(NULL);
}
#endif

static void _pal_device_register_init_0(void)
{
    if (upload_did) 
        free(upload_did);

    if (upload_diddoc)
        free(upload_diddoc);

    upload_did      = NULL;
    upload_diddoc   = NULL;

    if (device_register_key_id) {
        psa_destroy_key(device_register_key_id);
	    device_register_key_id = 0;        
    }

    memset(signature, 0, sizeof(signature)); 
    memset(signature_str, 0, sizeof(signature_str));
}

static int _pal_device_register_init(char *did)
{
    if (NULL == did)
        return -1;

    _pal_device_register_init_0();

    return 0;
}

void iotex_pal_sprout_device_register_start(char *did, char *diddoc)
{
    if (NULL == did || NULL == diddoc)
        return;

    int ret = _pal_device_register_init(did);
    if (ret) {
        printf("Failed to _pal_device_register_init() ret %d\n", ret);
    }

    upload_did    = iotex_utils_device_register_did_upload_prepare(did, 1, signature_str, true);
    if (upload_did)
        printf("Upload DID : %s\n", upload_did);

    upload_diddoc = iotex_utils_device_register_diddoc_upload_prepare(diddoc, 1, signature_str, true);
    if (upload_diddoc)
        printf("Upload DIDDoc : %s\n", upload_diddoc);     

#if (IOTEX_PAL_DEVICE_REGISTER_MODE == IOTEX_PAL_DEVICE_REGISTER_MODE_SERIAL)
        xTaskCreate(_sprout_device_register_serial_task, "device_register_task", 1024 * 5, NULL, 10, &pxCreatedTask);
#elif (IOTEX_PAL_DEVICE_REGISTER_MODE == IOTEX_PAL_DEVICE_REGISTER_MODE_HTTPS)
        _pal_sprout_webserver_secure_start();
#endif        

}

void iotex_pal_sprout_device_register_stop(void)
{
    _pal_device_register_init_0();
    
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



