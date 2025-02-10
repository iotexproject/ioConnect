#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "include/common.h"
#include "include/utils/iotex_dev_access.h"
#include "include/server/crypto.h"

#ifdef CONFIG_PSA_ITS_FLASH_C
#include "include/hal/flash/flash_common.h"
#endif

#ifdef CONFIG_PSA_ITS_NVS_C
#include "include/hal/nvs/nvs_common.h"
#endif

#include "DeviceConnect_Core.h"

static 	unsigned int deviceKeyID;
static 	unsigned int deviceKaKeyID;

static JWK *deviceJWK     = NULL;
static JWK *deviceKAJWK   = NULL;
static char *deviceDID    = NULL;
static char *deviceKID    = NULL;
static char *deviceKAKID  = NULL;
static char *DIDDoc_Serialize = NULL;

static int _util_api_prepare(void)
{
	if (deviceJWK)
		goto next_1;

	deviceJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
									IOTEX_JWK_LIFETIME_VOLATILE,
									PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
									PSA_ALG_ECDSA(PSA_ALG_SHA_256),
									&deviceKeyID);
	if (NULL == deviceJWK) {
		printf("Failed to generate JWK for device\n");
		return -1;
	}
	
next_1:
	if (deviceDID)
		goto next_2;

	deviceDID = iotex_did_generate("io", deviceJWK);
	if (NULL == deviceDID) {
		printf("Failed to generate did for device\n");
		return -2;
	}

next_2:
	if (deviceKID)
		goto next_3;

	deviceKID = iotex_jwk_generate_kid("io", deviceJWK);
    if (NULL == deviceKID) {
		printf("Failed to generate kid for device\n");
		return -3;
	}
    
next_3:
	if (deviceKAJWK)
		goto next_4;

		deviceKAJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
								IOTEX_JWK_LIFETIME_VOLATILE,
								PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
								PSA_ALG_ECDSA(PSA_ALG_SHA_256),
								&deviceKaKeyID);
	if (NULL == deviceKAJWK) {
		printf("Failed to generate KA JWK for device\n");
		return -4;
	}

next_4:
	if (deviceDID)
		goto next_5;

		deviceDID = iotex_did_generate("io", deviceJWK);
		if (NULL == deviceDID) {
			printf("Failed to generate did for device\n");
			return -5;
		}

next_5:
	if (deviceKAKID)
		goto next_6;

	deviceKAKID = iotex_jwk_generate_kid("io", deviceKAJWK);
	if (NULL == deviceKAKID) {
		printf("Failed to generate ka kid for device\n");
		return -6;
	}
	
next_6:
	if (DIDDoc_Serialize)
		goto next_7;
	
	did_status_t did_status;

	DIDDoc * deviceDIDDoc = iotex_diddoc_new();
	if (NULL == deviceDIDDoc) {
		printf("Failed to new a DIDDoc for the device\n");
		return -7;
	}

	did_status = iotex_diddoc_property_set(deviceDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
	did_status = iotex_diddoc_property_set(deviceDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");
	did_status = iotex_diddoc_property_set(deviceDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, deviceDID);
	if (DID_SUCCESS != did_status) {
		printf("iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
		iotex_diddoc_destroy(deviceDIDDoc);
		return -8; 
	}

	// Make a verification method [type : authentication]
	DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(deviceDIDDoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);      
	if (NULL == vm_authentication) {
		printf("Failed to iotex_diddoc_verification_method_new()\n");
		iotex_diddoc_destroy(deviceDIDDoc);
		return -9; 
	}

	did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, deviceKID);
	if (DID_SUCCESS != did_status) {
		printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
		iotex_diddoc_destroy(deviceDIDDoc);
		return -10; 
	}

	VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
	did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, deviceKID);
	did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
	did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, deviceDID);
	did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(deviceJWK));

	// Make a verification method [type : key agreement]
	DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(deviceDIDDoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);      
	if (NULL == vm_agreement) {
		printf("Failed to iotex_diddoc_verification_method_new()\n");
		iotex_diddoc_destroy(deviceDIDDoc);
		return -11;
	}

	did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, deviceKAKID);
	if (DID_SUCCESS != did_status) {
		printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
		iotex_diddoc_destroy(deviceDIDDoc);
		return -12; 
	} 

	VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
	did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, deviceKAKID);
	did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
	did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, deviceDID);
	did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(deviceKAJWK));

	DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(deviceDIDDoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
	did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
	did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

	DIDDoc_Serialize = iotex_diddoc_serialize(deviceDIDDoc, true);

	iotex_diddoc_destroy(deviceDIDDoc);

next_7:
	return 0;
}

static int _util_api_unprepare(void)
{
	static JWK *deviceJWK     = NULL;
	if (deviceJWK)
		iotex_jwk_destroy(deviceJWK);

	if (deviceKAJWK)
		iotex_jwk_destroy(deviceKAJWK);

	if (deviceDID)
		free(deviceDID);

	if (deviceKID)
		free(deviceKID);

	if (deviceKAKID)
		free(deviceKAKID);

	if (DIDDoc_Serialize)
		free(DIDDoc_Serialize);
	
	return 0;
}

int iotex_utils_api_init(void)
{
	psa_status_t status = psa_crypto_init();
	if (PSA_SUCCESS != status)
		return -1;

	return _util_api_prepare();
}

int iotex_utils_api_deinit(void)
{
	return _util_api_unprepare();
}

const char * iotex_utils_api_generate_device_did(void)
{
	return deviceDID;
}

const char * iotex_utils_api_generate_device_diddoc(void)
{
	return DIDDoc_Serialize;
}
