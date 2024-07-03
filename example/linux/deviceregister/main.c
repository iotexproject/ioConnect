#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <microhttpd.h>
#include "DeviceConnect_Core.h"
#include "deviceregister.h"

int main (void) {

    psa_status_t status = psa_crypto_init();
    if (PSA_SUCCESS != status)
        return 0;

    //************************ STEP. 1 ******************************//
    // Generate my own two JWKs 
    // One of them is used for signing and the other is used for key exchange 
    
    unsigned int mySignKeyID, myKeyAgreementKeyID;  

    mySignKeyID = 1; 
    JWK *mySignJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
                            IOTEX_JWK_LIFETIME_PERSISTENT,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                            &mySignKeyID);    
    if (NULL == mySignJWK) {
        printf("Failed to Generate a our own Sign JWK\n");
        goto exit;
    }

    myKeyAgreementKeyID = 2;
    JWK *myKAJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                        IOTEX_JWK_LIFETIME_PERSISTENT,
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

    char *mySignKID = iotex_jwk_generate_kid("io", mySignJWK);
    if (NULL == mySignKID)
        goto exit;    

    char *myKAKID = iotex_jwk_generate_kid("io", myKAJWK);
    if (NULL == myKAKID)
        goto exit;

    iotex_registry_item_register(myKAKID, myKAJWK);

    //********************** Step.3  Generate DIDDoc based on DID ************************//        
    did_status_t did_status;

    DIDDoc* myDIDDoc = iotex_diddoc_new();
    if (NULL == myDIDDoc) {
        printf("Failed to new a DIDDoc\n");
        goto exit;
    }

    did_status = iotex_diddoc_property_set(myDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
    did_status = iotex_diddoc_property_set(myDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");
    did_status = iotex_diddoc_property_set(myDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, mySignDID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
        goto exit; 
    }

    // 3.1 Make a verification method [type : authentication]
    DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(myDIDDoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);      
    if (NULL == vm_authentication) {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }
  
    did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, mySignKID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        goto exit; 
    }

    VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, mySignKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, mySignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(mySignJWK));

    // 3.2 Make a verification method [type : key agreement]
    DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(myDIDDoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);      
    if (NULL == vm_agreement) {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }
  
    did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, myKAKID);
    if (DID_SUCCESS != did_status) {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        goto exit; 
    } 

    VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, myKAKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, mySignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(myKAJWK));

    DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(myDIDDoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

    char *myDIDDoc_Serialize = iotex_diddoc_serialize(myDIDDoc, true);
    if (myDIDDoc_Serialize)
        printf("DIDdoc : \n%s\n", myDIDDoc_Serialize);

    iotex_pal_sprout_device_register_start(mySignDID, myDIDDoc_Serialize);

exit:          
    while(1) {
        sleep(1000);
    }

    return 0;
}