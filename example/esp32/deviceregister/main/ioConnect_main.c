/* WiFi station Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "DeviceConnect_Core.h"
#include "sprout.h"
#include "deviceregister.h"                        

/* The examples use WiFi configuration that you can set via project configuration menu

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

#if CONFIG_ESP_WIFI_AUTH_OPEN
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_OPEN
#elif CONFIG_ESP_WIFI_AUTH_WEP
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WEP
#elif CONFIG_ESP_WIFI_AUTH_WPA_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WAPI_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WAPI_PSK
#endif

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG = "wifi station";

static int s_retry_num = 0;

char *myDID    = NULL;
char *myDIDDoc = NULL;

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .password = EXAMPLE_ESP_WIFI_PASS,
            /* Authmode threshold resets to WPA2 as default if password matches WPA2 standards (pasword len => 8).
             * If you want to connect the device to deprecated WEP/WPA networks, Please set the threshold value
             * to WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK and set the password with length and format matching to
	     * WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK standards.
             */
            .threshold.authmode = ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap SSID:%s password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to SSID:%s, password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }
}

void app_main(void)
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();

    //********************** Step.0  ioConnect SDK initialization ***************************//
    default_SetSeed(esp_random());
    iotex_deviceconnect_sdk_core_init(NULL, NULL, NULL);

    //********************** Step.1  Generate the JWK for the device ************************//
    unsigned int key_id = 1;    
    unsigned int kakey_id = 2;    

    JWK *signjwk = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
                            IOTEX_JWK_LIFETIME_PERSISTENT,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                            &key_id);    
    if (NULL == signjwk) {
        printf("Fail to Generate a JWK\n");
        return;
    }

    char *sign_jwk_serialize = iotex_jwk_serialize(signjwk, true);
    if (sign_jwk_serialize)
        printf("JWK[Sign] : \n%s\n", sign_jwk_serialize);

    JWK *kajwk = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                            IOTEX_JWK_LIFETIME_PERSISTENT,
                            PSA_KEY_USAGE_DERIVE,
                            PSA_ALG_ECDH,
                            &kakey_id);    
    if (NULL == kajwk) {
        printf("Fail to Generate a JWK\n");
        return;
    }

    char *kajwk_serialize = iotex_jwk_serialize(kajwk, true);
    if (kajwk_serialize)
        printf("JWK[KA] : \n%s\n", kajwk_serialize);    
 
    //********************** Step.2  Generate DID based on JWK ************************//
    myDID = iotex_did_generate("io", signjwk);
    if (myDID)
        printf("DID : \n%s\n", myDID);

    char *myMasterkid = iotex_jwk_generate_kid("io", signjwk);
    if (NULL == myMasterkid)
        return;

    char *myKA_Kid = iotex_jwk_generate_kid("io", kajwk);
    if (NULL == myKA_Kid)
        return;

    //********************** Step.3  Generate DIDDoc based on DID ************************//
    DIDDoc* diddoc = iotex_diddoc_new();
    if (NULL == diddoc)
        return;

    did_status_t did_status = iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
    did_status = iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");

    did_status = iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, myDID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
        return;
    }

    DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);      
    if (NULL == vm_authentication) {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }
  
    did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, myMasterkid);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        return;
    }

    VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, myMasterkid);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, myDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(signjwk));  

    DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);      
    if (DID_SUCCESS == vm_agreement) {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }

    did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, myKA_Kid);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        return;
    } 

    VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, myKA_Kid);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, myDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(kajwk));

    DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

    myDIDDoc = iotex_diddoc_serialize(diddoc, true);
    if (myDIDDoc) {
        printf("DIDdoc [%d] : \n%s\n",strlen(myDIDDoc), myDIDDoc); 
    }

    //********************** Step.4  Start the device registration process ************************//
    iotex_pal_sprout_device_register_start(myDID, myDIDDoc);
    
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));         
    }    
}
