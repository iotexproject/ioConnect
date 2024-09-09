#include <stdio.h>
#include "DeviceConnect_Core.h"

psa_key_id_t g_sdkcore_key = 1;
static uint8_t exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256) + 1];
static uint8_t exported_dev_addr[64];

#ifdef ARDUINO
DevConn_Comm *g_commClient;
#endif

#if 0
static void iotex_export_public_key(void) {

    psa_status_t status;
    size_t exported_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    exported[0] = 0x4;
    status = psa_export_public_key( g_sdkcore_key, (uint8_t *)exported + 1, sizeof(exported) - 1, &exported_length );
    if( status != PSA_SUCCESS ) {

        printf("Generate a pair key...\n");

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
	    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	    psa_set_key_bits(&attributes, 256); 
        psa_set_key_id(&attributes, 1);
        
        status = psa_generate_key(&attributes, &g_sdkcore_key);
        if( status == PSA_SUCCESS ) {
            printf("Success to generate a pairkey keyid %d\n", g_sdkcore_key);
        } else {
            printf("Failed to generate a pairkey %d\n", status);
        }

        psa_export_public_key( g_sdkcore_key, (uint8_t *)exported + 1, sizeof(exported) - 1, &exported_length );
    }

    printf("export key :\n");
    for (int i = 0; i < exported_length + 1; i++)
        printf("%.2x ", exported[i]);
    printf("\n");

    iotex_dev_access_generate_dev_addr(exported, (char *)exported_dev_addr);
    printf("Wallet Addr : %s\n", exported_dev_addr);
}
#endif

#ifdef ARDUINO
uint8_t * iotex_deviceconnect_sdk_core_init(DevConn_Comm *commClient)
#else
uint8_t * iotex_deviceconnect_sdk_core_init(iotex_gettime get_time_func, iotex_mqtt_pub mqtt_pub, iotex_mqtt_sub mqtt_sub) 
#endif
{
    psa_crypto_init();
    iotex_dev_access_init();

#ifdef ARDUINO
    g_commClient = commClient;
#else
    iotex_dev_access_set_time_func(get_time_func);
    iotex_dev_access_set_mqtt_func(mqtt_pub, mqtt_sub);
#endif

    // iotex_export_public_key();

    // InitLowsCalc();

#ifdef IOTEX_SIGN_VERIFY_TEST
    psa_status_t status;
    unsigned char inbuf[] = "iotex_ecdsa_test_only";
	unsigned char buf[65] = {0};
    unsigned int  sinlen   = 0;

    status = psa_sign_message( g_sdkcore_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), inbuf, strlen((const char *)inbuf) + 1, (unsigned char *)buf, 65, &sinlen);
    if (status != PSA_SUCCESS) {
		printf("Failed to sign message %d\n", status);
	} else {
        printf("Success to sign message %d\n", sinlen);
    }

    status = psa_verify_message( g_sdkcore_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), inbuf, strlen((const char *)inbuf) + 1, (unsigned char *)buf, sinlen);
    if (status != PSA_SUCCESS) {
		printf("Failed to verify message %d\n", status);
	} else  {
        printf("Success to verify message\n");
    }
#endif

	return (uint8_t *)exported;
}

uint8_t * iotex_deviceconnect_sdk_core_get_public_key(void) {

    return (uint8_t *)exported;
}

uint8_t * iotex_deviceconnect_sdk_core_get_eth_addr(void) {

    return (uint8_t *)exported_dev_addr;
}

#ifdef ARDUINO
int iotex_device_connect_mqtt_pub(unsigned char *topic, unsigned char *buf, unsigned int buflen, int qos) {

    if (g_commClient)
        g_commClient->_mqttclient.publish((const char *)topic, buf, buflen);
    else
        return 0;

    return 1;
}
#endif

void iotex_ioconnect_core_init(void)
{
    psa_crypto_init();   
}  

