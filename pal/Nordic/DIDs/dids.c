#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>

#include "psa/crypto.h"
#include "include/jose/jose.h"
#include "include/dids/dids.h"

LOG_MODULE_REGISTER(jose, CONFIG_ASSET_TRACKER_LOG_LEVEL);

static JWK *signJWK = NULL;
static JWK *kaJWK   = NULL;

static char *deviceDID = NULL;
static char *deviceKID = NULL;
static char *deviceKAKID  = NULL;
static char *deviceDIDDoc = NULL;

char *iotex_pal_jose_device_did_get(void)
{
    return deviceDID;
}

char *iotex_pal_jose_device_kid_get(void)
{
    return deviceKID;
}

char *iotex_pal_jose_device_kakid_get(void)
{
    return deviceKAKID;
}

int iotex_pal_jose_generate_jwk(void)
{
    unsigned int signkey_id = 1; 
    signJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
                            IOTEX_JWK_LIFETIME_PERSISTENT,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                            &signkey_id);
    if (NULL == signJWK) {
        LOG_ERR("Fail to generate a master JWK");
        LOG_ERR("System will not startup");
        return -1;
    }     

#if 0
    char * signJWK_Serialize = iotex_jwk_serialize(signJWK, true);
    LOG_INF("signJWK : \n%s\n", signJWK_Serialize);
#endif

    deviceDID = iotex_did_generate("io", signJWK);
    if (deviceDID)
        LOG_INF("Device DID : %s", deviceDID);
    else
        return -1;

    unsigned int kakey_id = 2; 
    kaJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                            IOTEX_JWK_LIFETIME_PERSISTENT,
                            PSA_KEY_USAGE_DERIVE,
                            PSA_ALG_ECDH,
                            &kakey_id);
    if (NULL == kaJWK) {
        LOG_ERR("Fail to Generate a JWK for Key Agreement\n");
        LOG_ERR("System will not startup");
        goto exit_1;
    } 

#if 0
    char *kaJWK_Serialize = iotex_jwk_serialize(kaJWK, true);
    LOG_INF("kaJWK : \n%s", kaJWK_Serialize);
#endif

    deviceKID = iotex_jwk_generate_kid("io", signJWK);
    if (NULL == deviceKID)
        goto exit_1;

    LOG_INF("Device KID : %s", deviceKID);

    deviceKAKID = iotex_jwk_generate_kid("io", kaJWK);
    if (NULL == deviceKAKID)
        goto exit_2;    
                             
    LOG_INF("Device KA KID : %s", deviceKAKID);

    iotex_registry_item_register(deviceKAKID, kaJWK);

    return 0;

exit_2:
    if (deviceKID) {
        free (deviceKID);
        deviceDID = NULL;
    }    

exit_1:
    if (deviceDID) {
        free (deviceDID);
        deviceDID = NULL;
    }

    return -1;
}

char * iotex_pal_jose_generate_diddoc(void)
{
    if (deviceDIDDoc)
        return deviceDIDDoc;

    if (NULL == deviceDID || NULL == deviceKAKID)
        return NULL;

    DIDDoc* diddoc = iotex_diddoc_new();
    if (NULL == diddoc)
        goto exit;

    did_status_t did_status = iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
    did_status = iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");

    did_status = iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, deviceDID);
    if (DID_SUCCESS != did_status) {
        LOG_ERR("iotex_diddoc_property_set [%d] ret %d", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
        goto exit;
    }

    DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);      
    if (NULL == vm_authentication) {
        LOG_ERR("Failed to iotex_diddoc_verification_method_new()\n");
        goto exit;
    }
  
    did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, deviceKID);
    if (DID_SUCCESS != did_status) {
        LOG_ERR("iotex_diddoc_verification_method_set ret %d", did_status);
        goto exit;
    }

    VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, deviceKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, deviceDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(signJWK));  

    DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);      
    if (DID_SUCCESS == vm_agreement) {
        LOG_ERR("Failed to iotex_diddoc_verification_method_new()");
        goto exit;
    }

    did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, deviceKAKID);
    if (DID_SUCCESS != did_status) {
        LOG_ERR("iotex_diddoc_verification_method_set ret %d", did_status);
        goto exit;
    } 

    VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, deviceKAKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, deviceKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(kaJWK));

    DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

    deviceDIDDoc = iotex_diddoc_serialize(diddoc, true);
    if (NULL == deviceDIDDoc)
        goto exit;

    LOG_INF("DIDdoc [%d] : \n%s", strlen(deviceDIDDoc), deviceDIDDoc);
 
    return deviceDIDDoc;

exit:
    if (diddoc)    
        iotex_diddoc_destroy(diddoc);

    return NULL;
}








