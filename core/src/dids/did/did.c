#include <stdlib.h>
#include <string.h>

#include "include/psa/crypto.h"
#include "include/jose/jwk.h"
#include "include/dids/did/did.h"
#include "include/dids/did/did_key.h"
#include "include/dids/did/did_io.h"
#include "include/utils/cJSON/cJSON.h"

#define VERIFIABLE_RELATIONSHIP_TYPE_AUTHENTICATION     "authentication"
#define VERIFIABLE_RELATIONSHIP_TYPE_ASSERTIONMETHOD    "assertionMethod"
#define VERIFIABLE_RELATIONSHIP_TYPE_KEYAGREEMENT       "keyAgreement"
#define VERIFIABLE_RELATIONSHIP_TYPE_CONTRACTAGREEMENT  "contractAgreement"
#define VERIFIABLE_RELATIONSHIP_TYPE_CAP_INVOCATION     "capabilityInvocation"
#define VERIFIABLE_RELATIONSHIP_TYPE_CAP_DELEGATION     "capabilityDelegation"

#define DID_METHODS_MAX_NUM     4

typedef struct {
    char method_name[8];
    DID_Method *method;
} DID_Methods;

static DID_Methods g_method[DID_METHODS_MAX_NUM] = {{DID_METHOD_KEY_NAME, &did_key_method}, {DID_METHOD_IO_NAME, &did_io_method}, {0}, {0}};

enum VerificationRelationship get_verification_relationship_default(void)
{
    return AssertionMethod;
}

enum VerificationRelationship get_verification_relationship_from_str(char *str)
{
    if ( NULL == str )
        return VR_None;

    if ( 0 == strcmp(str, "authentication") )
        return Authentication;
    else if ( 0 == strcmp(str, "assertionMethod") )
        return AssertionMethod;
    else if ( 0 == strcmp(str, "keyAgreement") )
        return KeyAgreement;
    else if ( 0 == strcmp(str, "contractAgreement") )
        return ContractAgreement;
    else if ( 0 == strcmp(str, "capabilityInvocation") )
        return CapabilityInvocation;
    else if ( 0 == strcmp(str, "capabilityDelegation") )
        return CapabilityDelegation;

    return VR_None; 
}

char* verification_relationship_to_str(enum VerificationRelationship ship)
{
    switch (ship)
    {
    case AssertionMethod:
        return VERIFIABLE_RELATIONSHIP_TYPE_ASSERTIONMETHOD;
    case Authentication:
        return VERIFIABLE_RELATIONSHIP_TYPE_AUTHENTICATION;
    case KeyAgreement:
        return VERIFIABLE_RELATIONSHIP_TYPE_KEYAGREEMENT;
    case ContractAgreement:
        return VERIFIABLE_RELATIONSHIP_TYPE_CONTRACTAGREEMENT;
    case CapabilityInvocation:
        return VERIFIABLE_RELATIONSHIP_TYPE_CAP_INVOCATION;
    case CapabilityDelegation:
        return VERIFIABLE_RELATIONSHIP_TYPE_CAP_DELEGATION;
    default:
        break;
    }

    return NULL;
}

char* verification_relationship_to_iri(enum VerificationRelationship ship)
{
    switch (ship)
    {
    case AssertionMethod:
        return "https://w3id.org/security#assertionMethod";
    case Authentication:
        return "https://w3id.org/security#authenticationMethod";
    case KeyAgreement:
        return "https://w3id.org/security#keyAgreementMethod";
    case ContractAgreement:
        return "https://w3id.org/security#contractAgreementMethod";
    case CapabilityInvocation:
        return "https://w3id.org/security#capabilityInvocationMethod";
    case CapabilityDelegation:
        return "https://w3id.org/security#capabilityDelegationMethod";
    default:
        break;
    }

    return NULL;    
}

static DID_Method* get_did_method_with_method_name(char *name)
{
    if ( NULL == name )
        return NULL;

    for (int i = 0; i < DID_METHODS_MAX_NUM; i++) {
        if (NULL == g_method[i].method)
            continue;

        if (strcmp(name, g_method[i].method_name))            
            continue;

        return g_method[i].method;
    }

    return NULL;
}

char* iotex_did_generate(char *name, JWK *jwk)
{
    DID_Method *method = NULL;

    if ( NULL == name )
        return NULL;
    
    method = get_did_method_with_method_name(name);
    if (NULL == method) {
        printf("No match method\n");
        return NULL;
    }
    
    if (NULL == method->generate)
        return NULL;
    
    return method->generate(jwk);        
}

int iotex_dids_get_agreement_key(char *did, uint8_t *out, size_t *out_size)
{
    if (NULL == did || NULL == out || NULL == out_size)
        return -1;

#define IOTEX_TEST_FOR_PROCESS
#ifdef IOTEX_TEST_FOR_PROCESS
	uint8_t private[32] = {0};
	uint8_t public[2*32] = {0};

	const struct uECC_Curve_t * curve = uECC_secp256r1();

    if (!uECC_make_key(out, private, curve)) 
        return -2;

    *out_size = 64;

#endif        

    return 0;        
}

char *iotex_dids_get_default(char *did, JWK *jwk)
{
    char did_buf[128] = {0};

    if (NULL == did)
        return NULL;

    cJSON *diddoc = cJSON_CreateObject();

    cJSON *contexts = cJSON_CreateArray();

    cJSON_AddItemToArray(contexts, cJSON_CreateString("https://www.w3.org/ns/did/v1"));    
    cJSON_AddItemToArray(contexts, cJSON_CreateString("https://w3id.org/security#keyAgreementMethod"));
    cJSON_AddItemToObject(diddoc, "@context", contexts);

    cJSON_AddStringToObject(diddoc, "id", did);

    cJSON *key_agreements = cJSON_CreateArray();
    memcpy(did_buf, did, strlen(did));
    memcpy(did_buf + strlen(did), "#key-p256-1", strlen("#key-p256-1"));
    cJSON_AddItemToArray(key_agreements, cJSON_CreateString(did_buf));
    cJSON_AddItemToObject(diddoc, "keyAgreement", key_agreements);

    cJSON *verification_methods = cJSON_CreateArray();

    cJSON *vm_p256_1 = cJSON_CreateObject();
    cJSON_AddStringToObject(vm_p256_1, "id", did_buf);
    cJSON_AddStringToObject(vm_p256_1, "type", "JsonWebKey2020");
    cJSON_AddStringToObject(vm_p256_1, "conttroller", did);
    cJSON_AddItemToObject(vm_p256_1, "publicKeyJwk", (cJSON *)_did_jwk_json_generate(jwk));

    cJSON_AddItemToArray(verification_methods, vm_p256_1);

    cJSON_AddItemToObject(diddoc, "verificationMethod", verification_methods);

    // return cJSON_PrintUnformatted(diddoc);
    return cJSON_Print(diddoc);

}
