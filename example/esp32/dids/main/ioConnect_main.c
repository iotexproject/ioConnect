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
    int sock = -1;

    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();

    //************************ Step.0 ioConnect SDK initialization ************************//
    default_SetSeed(esp_random());
    iotex_deviceconnect_sdk_core_init(NULL, NULL, NULL);    

    //************************ STEP. 1 ******************************//
    // Generate my own two JWKs 
    // One of them is used for signing and the other is used for key exchange 
    
    unsigned int mySignKeyID, myKeyAgreementKeyID;  

    mySignKeyID = 1; 

    JWK *mySignJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                            IOTEX_JWK_LIFETIME_PERSISTENT,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                            &mySignKeyID);    
    if (NULL == mySignJWK) {
        printf("Failed to Generate a our own Sign JWK\n");
        goto exit;
    }

    JWK *myKAJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                        IOTEX_JWK_LIFETIME_VOLATILE,
                        PSA_KEY_USAGE_DERIVE,
                        PSA_ALG_ECDH,
                        &myKeyAgreementKeyID);  
    if (NULL == myKAJWK) {
        printf("Failed to Generate a our own KeyAgreement JWK\n");
        goto exit;
    }  
  
    //************************ STEP. 2 ******************************//
    // Based on the JWK generated in Step 1, 
    // generate the corresponding DID and use the "io" method

    char *mySignDID = iotex_did_generate("io", mySignJWK);
    if (mySignDID)
        printf("My Sign DID : \t\t\t%s\n", mySignDID);
    else
        goto exit;

    char *myKADID = iotex_did_generate("io", myKAJWK);
    if (myKADID)
        printf("My Key Agreement DID : \t\t%s\n", myKADID);
    else
        goto exit;

    char *myKAKID = iotex_jwk_generate_kid("io", myKAJWK);
    if (NULL == myKAKID)
        goto exit;

    iotex_registry_item_register(myKAKID, myKAJWK);

    //************************ STEP. 3 ******************************//
    // In order to simulate C/S communication, 
    // we generate the JWK of the peer's key exchange and the corresponding DID.

    unsigned int peerSignKeyID, peerKeyAgreementKeyID;

    JWK *peerSignJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                        IOTEX_JWK_LIFETIME_VOLATILE,
                        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                        &peerSignKeyID);    
    if (NULL == peerSignJWK) {
        printf("Failed to Generate a peer Sign JWK\n");
        goto exit;
    }

    JWK *peerKAJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                        IOTEX_JWK_LIFETIME_VOLATILE,
                        PSA_KEY_USAGE_DERIVE,
                        PSA_ALG_ECDH,
                        &peerKeyAgreementKeyID);  
    if (NULL == peerKAJWK) {
        printf("Failed to Generate a peer KeyAgreement JWK\n");
        goto exit;
    }

    char *peerSignDID = iotex_did_generate("io", peerSignJWK);
    if (peerSignDID)
        printf("Peer DID : \t\t\t%s\n", peerSignDID);
    else
        goto exit;    

    char *peerKADID = iotex_did_generate("io", peerKAJWK);
    if (peerKADID)
        printf("Peer Key Agreement DID : \t%s\n", peerKADID);
    else
        goto exit;

    char *peerSignKID = iotex_jwk_generate_kid("io", peerSignJWK);
    if (NULL == peerSignKID)
        goto exit;        

    char *peerKAKID = iotex_jwk_generate_kid("io", peerKAJWK);
    if (NULL == peerKAKID)
        goto exit;

    iotex_registry_item_register(peerKAKID, peerKAJWK);        
        

    //************************ STEP. 4 ******************************//        
    // In order to simulate C/S communication, 
    // generate a DIDDoc for the peer.

    did_status_t did_status;

    DIDDoc* peerDIDDoc = iotex_diddoc_new();
    if (NULL == peerDIDDoc) {
        printf("Failed to new a peerDIDDoc\n");
        goto exit;
    }

    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, peerSignDID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
        goto exit; 
    }

    // 4.1 Make a verification method [type : authentication]
    DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);      
    if (NULL == vm_authentication) {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }
  
    did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, peerSignKID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        goto exit; 
    }

    VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerSignKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerSignJWK));

    // 4.2 Make a verification method [type : key agreement]
    DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);      
    if (NULL == vm_agreement) {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }
  
    did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, peerKAKID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        goto exit; 
    } 

    VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerKAKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerKAJWK));

    DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

    char *peerDIDDoc_Serialize = iotex_diddoc_serialize(peerDIDDoc, true);
    if (peerDIDDoc_Serialize)
        printf("DIDdoc : \n%s\n", peerDIDDoc_Serialize);

    iotex_diddoc_destroy(peerDIDDoc);

    // 4.3 Parse a DIDDoc
    DIDDoc *parsed_diddoc = iotex_diddoc_parse(peerDIDDoc_Serialize);

    if (parsed_diddoc)
        iotex_diddoc_destroy(parsed_diddoc);

    //************************ STEP. 5 ******************************//        
    // In order to simulate C/S communication, 
    // generate a VC.   

    vc_handle_t vc_handle = iotex_vc_new();
    did_status = iotex_vc_property_set(vc_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, IOTEX_CREDENTIALS_V1_CONTEXT);
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT, did_status);
        goto exit; 
    }
    did_status = iotex_vc_property_set(vc_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/2018/credentials/examples/v1");    
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT, did_status);
        goto exit; 
    }

    did_status = iotex_vc_property_set(vc_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_ID, NULL, "http://example.org/credentials/3731");    
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_ID, did_status);
        goto exit; 
    }

    did_status = iotex_vc_property_set(vc_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_TYPE, NULL, "VerifiableCredential");    
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_TYPE, did_status);
        goto exit; 
    }

    did_status = iotex_vc_property_set(vc_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID, NULL, mySignDID);    
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID, did_status);
        goto exit; 
    } 

    did_status = iotex_vc_property_set(vc_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER_DATE, NULL, "2020-08-19T21:41:50Z");    
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER_DATE, did_status);
        goto exit; 
    }

    property_handle_t property_cs_handle = iotex_vc_sub_property_new();             
    did_status = iotex_vc_sub_property_set(property_cs_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_CS | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID, NULL, peerSignDID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_sub_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_CS | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID, did_status);
        goto exit; 
    }    
    did_status = iotex_vc_property_set(vc_handle, IOTEX_VC_BUILD_PROPERTY_TYPE_CS, NULL, property_cs_handle);    
    if (DID_SUCCESS != did_status) {
        printf("iotex_vc_property_set [%d] ret %d\n", IOTEX_VC_BUILD_PROPERTY_TYPE_CS, did_status);
        goto exit; 
    }    

    char * vc_serialize = iotex_vc_serialize(vc_handle, true);
    if (vc_serialize)
        printf("VC :\n%s\n", vc_serialize);

    iotex_vc_destroy(vc_handle);        

    //************************ STEP. 6 ******************************//                  
    // Generate a JWT by signing the VC generated in Step 5.

    JWTClaim_handle jwt_claim_handle = iotex_jwt_claim_new();
    if (NULL == jwt_claim_handle) {
        printf("Fail to Generate a jwt claim\n");
        goto exit;
    }

    did_status = iotex_jwt_claim_set_value(jwt_claim_handle, JWT_CLAIM_TYPE_ISS, NULL, (void *)mySignDID);
    if (vc_serialize) {
        cJSON *priObjct = IOTEX_VC_PARSE_TO_OBJECT(vc_serialize);
        did_status = iotex_jwt_claim_set_value(jwt_claim_handle, JWT_CLAIM_TYPE_PRIVATE_JSON, "vp", priObjct);
        cJSON_Delete(priObjct);
    } else {
        printf("Dont find a valid VC/n");
        goto exit;
    }
    
    char *jwt_serialize = iotex_jwt_serialize(jwt_claim_handle, JWT_TYPE_JWS, ES256, mySignJWK);    
    if (jwt_serialize)
        printf("JWT[JWS]:\n%s\n", jwt_serialize);

    iotex_jwt_claim_destroy(jwt_claim_handle);

    //************************ STEP. 7 ******************************// 
    char *vp_serialize = NULL;
    char *iss = iotex_jwt_claim_get_value(jwt_serialize, JWT_TYPE_JWS, JWT_CLAIM_TYPE_ISS, NULL);
    if (iss) 
        printf("Get ISS : %s\n", iss);

    cJSON *vp = iotex_jwt_claim_get_value(jwt_serialize, JWT_TYPE_JWS, JWT_CLAIM_TYPE_PRIVATE_JSON, "vp");
    if (vp) {
        vp_serialize = cJSON_Print(vp);
        printf("Get Private Json : %s\n", vp_serialize);
    }

    char *subject_id = iotex_vc_property_get(vp_serialize, IOTEX_VC_BUILD_PROPERTY_TYPE_CS | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID, NULL, 0);
    if (subject_id)
        printf("Get Subject ID : %s\n", subject_id);                       

    //************************ STEP. 7 ******************************//                  
    // To verigy the JWT.     

    if (iotex_jwt_verify(jwt_serialize, JWT_TYPE_JWS, ES256, mySignJWK))
        printf("Success to JWT [JWS] Verify\n");
    else
        printf("Fail to JWT [JWS] Verify\n");

    //************************ STEP. 8 ******************************//
    // In order to simulate C/S communication,                  
    // to generate a client DIDcomm Message. 

    char *recipients_kid[JOSE_JWE_RECIPIENTS_MAX] = {0};
    recipients_kid[0] = myKAKID;
    char *jwe_json = iotex_jwe_encrypt("This is a JWE Test", Ecdh1puA256kw, A256cbcHs512, peerSignDID, peerSignJWK, recipients_kid, true);
    if (jwe_json)      
        printf("JWE JSON Serialize : \n%s\n", jwe_json);

    //************************ STEP. 8 ******************************//
    // To Decrypt the DIDComm Message from client. 

    char *jwe_plaintext = iotex_jwe_decrypt(jwe_json, Ecdh1puA256kw, A256cbcHs512, peerSignDID, peerSignJWK, myKAKID);
    if (jwe_plaintext)
        printf("JWE Decrypted Plaintext : \n%s\n", jwe_plaintext);            

    //************************ Free Res ****************************//  
    if (jwe_plaintext)
        free(jwe_plaintext);

    if (jwe_json)
        free(jwe_json);

    if (jwt_serialize)
        free(jwt_serialize);

    if (vc_serialize)
        free(vc_serialize);

    if (peerDIDDoc_Serialize)
        free(peerDIDDoc_Serialize);

    if (mySignDID)
        free(mySignDID);

    if (myKADID)
        free(myKADID);

    iotex_registry_item_unregister(myKAKID);        
    if (myKAKID)
        free(myKAKID);        

    if (peerSignDID)
        free(peerSignDID);

    if (peerKADID)
        free(peerKADID);

    iotex_registry_item_unregister(peerKAKID);        
    if (peerKAKID)
        free(peerKAKID);

    if (iss)
        free(iss);

    if (subject_id)
        free(subject_id);

    if (vp_serialize)
        free(vp_serialize);        

    if (vp)
        cJSON_Delete(vp);

    if (peerSignKID)
        free(peerSignKID);

    iotex_jwk_destroy(mySignJWK);        
    iotex_jwk_destroy(myKAJWK);
    iotex_jwk_destroy(peerSignJWK);
    iotex_jwk_destroy(peerKAJWK);

exit:
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));         
    }    
}
