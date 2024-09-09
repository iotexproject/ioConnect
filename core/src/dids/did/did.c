#include <stdlib.h>
#include <string.h>

#include "include/server/crypto.h"
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

// static DID_Methods g_method[DID_METHODS_MAX_NUM] = {{DID_METHOD_KEY_NAME, &did_key_method}, {DID_METHOD_IO_NAME, &did_io_method}, {0}, {0}};
static DID_Methods g_method[DID_METHODS_MAX_NUM] = {
    { {DID_METHOD_KEY_NAME}, &did_key_method },
    { {DID_METHOD_IO_NAME}, &did_io_method },
    { {0}, NULL },
    { {0}, NULL }
};

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

#define IOTEX_TEST_FOR_PROCESS
#ifdef IOTEX_TEST_FOR_PROCESS

#include "include/backends/tinycryt/ecc.h"
#include "include/backends/tinycryt/ecc_dh.h"

#endif

int iotex_dids_get_agreement_key(char *did, uint8_t *out, size_t *out_size)
{
    if (NULL == did || NULL == out || NULL == out_size)
        return -1;

#ifdef IOTEX_TEST_FOR_PROCESS

	uint8_t private[32] = {0};
	// uint8_t public[2*32] = {0};

	const struct uECC_Curve_t * curve = uECC_secp256r1();

    if (!uECC_make_key(out, private, curve)) 
        return -2;

    *out_size = 64;

#endif        

    return 0;        
}

static void *_build_diddoc_service_object(DIDDoc_Service *service)
{
    size_t array_size = 0;

    if (NULL == service)
        return NULL;

    if ((!service->id[0]) && (NULL == service->type) && (NULL == service->endpoints))
        return NULL;

    cJSON *service_obj = cJSON_CreateObject();
    if (NULL == service_obj)
        return NULL;

    if (service->id[0])
        cJSON_AddStringToObject(service_obj, "id", service->id);

    if (service->type)
        array_size = cJSON_GetArraySize(service->type);

    if (!array_size)
        goto next;

    if (service->type) {
        if (1 == array_size) {
            cJSON *serviceType = cJSON_GetArrayItem(service->type, 0);
            if (cJSON_IsString(serviceType))
                cJSON_AddStringToObject(service_obj, "type", serviceType->valuestring);
        }
        else 
            cJSON_AddItemToObject(service_obj, "type", service->type);
    }

    array_size = 0;
next:
    if (service->endpoints) {
        if (1 == array_size) {
            cJSON *endpoints = cJSON_GetArrayItem(service->endpoints, 0);
            if (cJSON_IsString(endpoints))
                cJSON_AddStringToObject(service_obj, "serviceEndpoint", endpoints->valuestring);
            else 
                cJSON_AddItemToObject(service_obj, "serviceEndpoint", endpoints);
        }
        else 
            cJSON_AddItemToObject(service_obj, "serviceEndpoint", service->endpoints);
    }

    return (void *)service_obj;         
}

DIDDoc* iotex_diddoc_new(void)
{
    return calloc(sizeof(DIDDoc), sizeof(char));
}

void iotex_diddoc_destroy(DIDDoc *doc)
{
    if (NULL == doc)
        return;

    if (doc->contexts.contexts)
        cJSON_Delete(doc->contexts.contexts);

    if (doc->aka.alsoKnownAs) 
        cJSON_Delete(doc->aka.alsoKnownAs);

    if (doc->cons.controllers)
        cJSON_Delete(doc->cons.controllers);

    if (doc->vm.vm)
        cJSON_Delete(doc->vm.vm);

    if (doc->auth.vm)
        cJSON_Delete(doc->auth.vm);

    if (doc->assertion.vm)
        cJSON_Delete(doc->assertion.vm);

    if (doc->keyagreement.vm)
        cJSON_Delete(doc->keyagreement.vm);

    if (doc->ci.vm)
        cJSON_Delete(doc->ci.vm);

    if (doc->cd.vm)
        cJSON_Delete(doc->cd.vm);

    if (doc->publickey.vm)
        cJSON_Delete(doc->publickey.vm);

    if (doc->services.Services)
        cJSON_Delete(doc->services.Services);

    if (doc->property_set)
        cJSON_Delete(doc->property_set);

    free(doc);

}

DIDDoc_VerificationMethod* iotex_diddoc_verification_method_new(DIDDoc* diddoc, enum VerificationMethod_Purpose purpose, enum VerificationMethod_Type type)
{
    DIDDoc_VerificationMethod *vm = NULL;

    if (NULL == diddoc)
        return (DIDDoc_VerificationMethod *)NULL;

    switch (purpose) {
        case VM_PURPOSE_VERIFICATION_METHOD:
            vm = &diddoc->vm;
            break;
        case VM_PURPOSE_AUTHENTICATION:
            vm = &diddoc->auth;
            break;
        case VM_PURPOSE_ASSERTION_METHOD:
            vm = &diddoc->assertion;
            break;
        case VM_PURPOSE_KEY_AGREEMENT:
            vm = &diddoc->keyagreement;
            break;
        case VM_PURPOSE_CAPABILITY_INVOCATION:
            vm = &diddoc->ci;
            break;
        case VM_PURPOSE_CAPABILITY_DELEGATION:
            vm = &diddoc->cd;
            break;
        case VM_PURPOSE_PUBLIC_KEY:
            vm = &diddoc->publickey;
            break;                                                
        default:
            return (DIDDoc_VerificationMethod *)NULL;
    }

    if (vm->vm)
        cJSON_Delete(vm->vm);

    switch (type) {
        case VM_TYPE_DIDURL:
        case VM_TYPE_MAP:
            vm->vm = cJSON_CreateArray();
            break;;    
        default:
            return (DIDDoc_VerificationMethod *)NULL;
    }

    vm->purpose = purpose;
    vm->type    = type;

    return vm;
}

VerificationMethod_Map iotex_diddoc_verification_method_map_new(void)
{
    return (VerificationMethod_Map)cJSON_CreateObject();
}

did_status_t iotex_diddoc_verification_method_map_set(VerificationMethod_Map map, unsigned int build_type, void *value)
{
    if (NULL == map)
        return DID_ERROR_INVALID_ARGUMENT;
    
    if (NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;

    switch (IOTEX_DIDDOC_GET_BUILD_VM_MAP_TYPE(build_type)) {
        case IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID:
            cJSON_AddStringToObject(map, "id", (char *)value);   
            break;
        case IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE:
            cJSON_AddStringToObject(map, "type", (char *)value);   
            break;
        case IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON:
            cJSON_AddStringToObject(map, "controller", (char *)value);   
            break;  
        case IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_MULTIBASE: 
            cJSON_AddStringToObject(map, "publicKeyMultibase", (char *)value);   
            break;   
        case IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_BASE58: 
            cJSON_AddStringToObject(map, "publicKeyBase58", (char *)value);   
            break;                                               
        case IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK: 
            cJSON_AddItemToObject(map, "publicKeyJwk", (cJSON *)value);   
            break;          
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }

    return DID_SUCCESS;
}

did_status_t iotex_diddoc_verification_method_set(DIDDoc_VerificationMethod *vm, enum VerificationMethod_Type type, void *value)
{
    if (NULL == vm || NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;

    if (vm->type != type)        
        return DID_ERROR_INVALID_ARGUMENT;

    switch (type) {
        case VM_TYPE_DIDURL:
            cJSON_AddItemToArray(vm->vm, cJSON_CreateString(value));
            break;
        case VM_TYPE_MAP:
            cJSON_AddItemToArray(vm->vm, (cJSON *)value);     
            break;        
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }

    return DID_SUCCESS;
}

static did_status_t _diddoc_sub_property_set(cJSON *object, unsigned int subtype, char *name, void *value)
{
    if (NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;

    if ((subtype & IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK) && (NULL == name))        
        return DID_ERROR_INVALID_ARGUMENT;

    switch (subtype) {
        case IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_STRING:
            cJSON_AddStringToObject(object, name, value);
            break;
        case IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_NUM:
            cJSON_AddNumberToObject(object, name, *(double *)value);
            break;
        case IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_BOOL:
            cJSON_AddBoolToObject(object, name, *(cJSON_bool *)value);
            break;
        case IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_JSON:
            cJSON_AddItemToObject(object, name, cJSON_Duplicate((cJSON *)value, true));
            break;                             
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }        

    return DID_SUCCESS;
}

did_status_t iotex_diddoc_property_set(DIDDoc *diddoc, unsigned int build_type, char *name, void *value)
{
    did_status_t status = DID_SUCCESS;

    if (NULL == diddoc || 0 == build_type || NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;
              
    switch (IOTEX_DIDDOC_GET_BUILD_PROPERTY_MAIN_TYPE(build_type)) {
        case IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT:
            
            if (NULL == diddoc->contexts.contexts) 
                diddoc->contexts.contexts = cJSON_CreateArray();
            
            cJSON_AddItemToArray(diddoc->contexts.contexts, cJSON_CreateString((const char *)value));            

            break;
        case IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID:

            if (strlen(value) >= IOTEX_DIDDOC_PROPERTY_ID_BUFFER_SIZE)
                return DID_ERROR_BUFFER_TOO_SMALL;

            if (diddoc->id[0])
                memset(diddoc->id, 0, IOTEX_DIDDOC_PROPERTY_ID_BUFFER_SIZE);

            strcpy(diddoc->id, (const char *)value);                
            break;
        case IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ALSO_KNOWN_AS:

            if (NULL == diddoc->aka.alsoKnownAs)
                diddoc->aka.alsoKnownAs = cJSON_CreateArray();

            cJSON_AddItemToArray(diddoc->aka.alsoKnownAs, cJSON_CreateString(value));  

            break;
        case IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTROLLER:

            if (NULL == diddoc->cons.controllers)
                diddoc->cons.controllers = cJSON_CreateArray();

            cJSON_AddItemToArray(diddoc->cons.controllers, cJSON_CreateString(value));  

            break;            
        case IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_PROPERTY:

            if (0 == IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_VALID(build_type))
                return DID_ERROR_INVALID_ARGUMENT;

            if (NULL == diddoc->property_set)
                diddoc->property_set = cJSON_CreateObject();

            status = _diddoc_sub_property_set(diddoc->property_set, IOTEX_DIDDOC_GET_BUILD_PROPERTY_SUB_TYPE(build_type), name, value);                
            if (DID_SUCCESS != status)
                return status;

            break;    
        case IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_SERVICE:

            if (NULL == diddoc->services.Services)
                diddoc->services.Services = cJSON_CreateArray();

            cJSON_AddItemToArray(diddoc->services.Services, (cJSON *)_build_diddoc_service_object((DIDDoc_Service *)value)); 

            break;                                                             
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }

    return DID_SUCCESS;            
}

DIDDoc_ServiceEndpoint* iotex_diddoc_service_endpoint_new(enum ServiceEndpoint_type type)
{
    DIDDoc_ServiceEndpoint *ServiceEndpoint = malloc(sizeof(DIDDoc_ServiceEndpoint));
    if (NULL == ServiceEndpoint)
        return NULL;

    switch (type) {
        case SERVICE_ENDPOINT_TYPE_URI:
        case SERVICE_ENDPOINT_TYPE_MAP:
            ServiceEndpoint->endpoint = cJSON_CreateArray();
            break;
        default:
            free(ServiceEndpoint);
            return NULL;
    }

    ServiceEndpoint->type = type;

    return ServiceEndpoint;
}

did_status_t iotex_diddoc_service_endpoint_set(DIDDoc_ServiceEndpoint* ServiceEndpoint, enum ServiceEndpoint_type type, void *value)
{
    if (NULL == ServiceEndpoint || NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;

    if (ServiceEndpoint->type != type)
        return DID_ERROR_INVALID_ARGUMENT;

    if (NULL == ServiceEndpoint->endpoint)
        return DID_ERROR_INVALID_ARGUMENT;

    switch (type) {
        case SERVICE_ENDPOINT_TYPE_URI:
            cJSON_AddItemToArray(ServiceEndpoint->endpoint, cJSON_CreateString(value));
            break;
        case SERVICE_ENDPOINT_TYPE_MAP:
            cJSON_AddItemToArray(ServiceEndpoint->endpoint, (cJSON *)value);
            break;
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    } 

    return DID_SUCCESS;           
}

DIDDoc_Service* iotex_diddoc_service_new(void)
{
    return (DIDDoc_Service *)calloc(sizeof(DIDDoc_Service), sizeof(char));
}

did_status_t iotex_diddoc_service_set(DIDDoc_Service* Service, unsigned int build_type, void *value)
{
    if (NULL == Service || NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;

    switch (IOTEX_DIDDOC_GET_BUILD_SERVICE_TYPE(build_type)) {
        case IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ID:

            memset(Service->id, 0, IOTEX_DIDDOC_PROPERTY_SERVICE_ID_BUFFER_SIZE);

            if (strlen(value) >= IOTEX_DIDDOC_PROPERTY_SERVICE_ID_BUFFER_SIZE)
                return DID_ERROR_INSUFFICIENT_MEMORY;

            strcpy(Service->id, (const char *)value);
            break;
        case IOTEX_DIDDOC_BUILD_SERVICE_TYPE_TYPE:

            if (NULL == Service->type)
                Service->type = cJSON_CreateArray();

            cJSON_AddItemToArray(Service->type, cJSON_CreateString((const char *)value));
            break;
        case IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ENDPOINT:

            if (NULL == Service->endpoints)
                Service->endpoints = cJSON_CreateArray();

            cJSON_AddItemToArray(Service->endpoints, (cJSON *)value);
            break;            
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    } 

    return DID_SUCCESS;           
}

char *iotex_diddoc_serialize(DIDDoc *diddoc, bool format)
{
    char *diddoc_serialize = NULL;

    if (NULL == diddoc)
        return NULL;

    cJSON * diddoc_obj = cJSON_CreateObject();
    if (NULL == diddoc_obj)
        return NULL;

    if (diddoc->contexts.contexts)
        cJSON_AddItemToObject(diddoc_obj, "@context", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->contexts.contexts));

    if (diddoc->id[0])
        cJSON_AddStringToObject(diddoc_obj, "id", diddoc->id);

    if (diddoc->aka.alsoKnownAs)
        cJSON_AddItemToObject(diddoc_obj, "alsoKnownAs", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->aka.alsoKnownAs));        

    if (diddoc->cons.controllers)
        cJSON_AddItemToObject(diddoc_obj, "controller", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->cons.controllers));

    if (diddoc->auth.vm)
        cJSON_AddItemToObject(diddoc_obj, "authentication", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->auth.vm));

    if (diddoc->assertion.vm)
        cJSON_AddItemToObject(diddoc_obj, "assertionMethod", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->assertion.vm));

    if (diddoc->keyagreement.vm)
        cJSON_AddItemToObject(diddoc_obj, "keyAgreement", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->keyagreement.vm));

    if (diddoc->ci.vm)
        cJSON_AddItemToObject(diddoc_obj, "capabilityInvocation", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->ci.vm));

    if (diddoc->cd.vm)
        cJSON_AddItemToObject(diddoc_obj, "capabilityDelegation", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->cd.vm));

    if (diddoc->publickey.vm)
        cJSON_AddItemToObject(diddoc_obj, "capabilityDelegation", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->publickey.vm)); 

    if (diddoc->vm.vm)
        cJSON_AddItemToObject(diddoc_obj, "verificationMethod", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->vm.vm));               

    if (diddoc->property_set)
        cJSON_AddItemToObject(diddoc_obj, "private", IOTEX_DIDDOC_PROPERTY_DUPLICATE(diddoc->property_set));

    if (format)
        diddoc_serialize = cJSON_Print(diddoc_obj);
    else        
        diddoc_serialize = cJSON_PrintUnformatted(diddoc_obj);
    
    cJSON_Delete(diddoc_obj);

    return diddoc_serialize;        
}

static did_status_t _diddoc_verification_method_build(DIDDoc_VerificationMethod *vm, cJSON *vm_item, enum VerificationMethod_Purpose purpose)
{
    if (NULL == vm || NULL == vm_item)
        return DID_ERROR_INVALID_ARGUMENT;

    if (!cJSON_IsArray(vm_item))
        return DID_ERROR_DATA_FORMAT;

    if (0 == cJSON_GetArraySize(vm_item))
        return DID_ERROR_DATA_FORMAT;
    
    if (cJSON_IsString( cJSON_GetArrayItem(vm_item, 0)))
        vm->type = VM_TYPE_DIDURL;
    else
        vm->type = VM_TYPE_MAP;

    vm->purpose = purpose;
    vm->vm = vm_item;

    return DID_SUCCESS;
}

static did_status_t _diddoc_verification_method_parse(DIDDoc *doc, cJSON *doc_root, enum VerificationMethod_Purpose purpose)
{
    if (NULL == doc || NULL == doc_root)
        return DID_ERROR_INVALID_ARGUMENT;

    switch (purpose) {
        case VM_PURPOSE_VERIFICATION_METHOD:
            doc->vm.vm = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(doc_root, "verificationMethod"));
            _diddoc_verification_method_build(&doc->vm, doc->vm.vm, VM_PURPOSE_VERIFICATION_METHOD);
            break;
        case VM_PURPOSE_AUTHENTICATION:
            doc->auth.vm = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(doc_root, "authentication"));
            _diddoc_verification_method_build(&doc->auth, doc->auth.vm, VM_PURPOSE_AUTHENTICATION);
            break;
        case VM_PURPOSE_ASSERTION_METHOD:
            doc->assertion.vm = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(doc_root, "assertionMethod"));
            _diddoc_verification_method_build(&doc->assertion, doc->assertion.vm, VM_PURPOSE_ASSERTION_METHOD);
            break;
        case VM_PURPOSE_KEY_AGREEMENT:
            doc->keyagreement.vm = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(doc_root, "keyAgreement"));
            _diddoc_verification_method_build(&doc->keyagreement, doc->keyagreement.vm, VM_PURPOSE_KEY_AGREEMENT);
            break;
        case VM_PURPOSE_CAPABILITY_INVOCATION:
            doc->ci.vm = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(doc_root, "capabilityInvocation"));
            _diddoc_verification_method_build(&doc->ci, doc->ci.vm, VM_PURPOSE_CAPABILITY_INVOCATION);
            break;
        case VM_PURPOSE_CAPABILITY_DELEGATION:
            doc->cd.vm = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(doc_root, "capabilityDelegation"));
            _diddoc_verification_method_build(&doc->cd, doc->cd.vm, VM_PURPOSE_CAPABILITY_DELEGATION);
            break;
        case VM_PURPOSE_PUBLIC_KEY:
            doc->publickey.vm = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(doc_root, "publicKey"));
            _diddoc_verification_method_build(&doc->publickey, doc->publickey.vm, VM_PURPOSE_PUBLIC_KEY);
            break;                                                                                  
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }

    return DID_SUCCESS;
}

DIDDoc *iotex_diddoc_parse(char *diddoc_serialize)
{
    if (NULL == diddoc_serialize)
        return NULL;

    cJSON *diddoc_obj = cJSON_Parse(diddoc_serialize);
    if (NULL == diddoc_obj)
        return NULL;

    DIDDoc *diddoc = calloc(sizeof(DIDDoc), sizeof(1));
    if (NULL == diddoc)
        goto exit;

    diddoc->contexts.contexts = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(diddoc_obj, "@context"));

    cJSON *id_item = cJSON_GetObjectItem(diddoc_obj, "id");
    if (id_item && cJSON_IsString(id_item) && (strlen(id_item->valuestring) < IOTEX_DIDDOC_PROPERTY_ID_BUFFER_SIZE))
        strcpy(diddoc->id,  id_item->valuestring);

    diddoc->aka.alsoKnownAs  = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(diddoc_obj, "alsoKnownAs"));
    diddoc->cons.controllers = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(diddoc_obj, "controller"));

    for (int i = (int)VM_PURPOSE_VERIFICATION_METHOD; i < (int)VM_PURPOSE_MAX; i++)
        _diddoc_verification_method_parse(diddoc, diddoc_obj, (enum VerificationMethod_Purpose)i);    

    diddoc->services.Services = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(diddoc_obj, "service"));
    diddoc->property_set      = IOTEX_DIDDOC_PROPERTY_DUPLICATE(cJSON_GetObjectItem(diddoc_obj, "private"));

exit:
    if (diddoc_obj)
        cJSON_Delete(diddoc_obj);

    return diddoc;
}

unsigned int iotex_diddoc_verification_method_get_num(DIDDoc *diddoc, enum VerificationMethod_Purpose purpose)
{
    if (NULL == diddoc)
        return 0;

    switch (purpose) {
        case VM_PURPOSE_VERIFICATION_METHOD:            
            if ((diddoc->vm.vm) && cJSON_IsArray(diddoc->vm.vm))
                return  (unsigned int)cJSON_GetArraySize(diddoc->vm.vm);
            break;
        case VM_PURPOSE_AUTHENTICATION:
            if ((diddoc->auth.vm) && cJSON_IsArray(diddoc->auth.vm))
                return  (unsigned int)cJSON_GetArraySize(diddoc->auth.vm);
            break;
        case VM_PURPOSE_ASSERTION_METHOD:
            if ((diddoc->assertion.vm) && cJSON_IsArray(diddoc->assertion.vm))
                return  (unsigned int)cJSON_GetArraySize(diddoc->assertion.vm);
            break;
        case VM_PURPOSE_KEY_AGREEMENT:
            if ((diddoc->keyagreement.vm) && cJSON_IsArray(diddoc->keyagreement.vm))
                return  (unsigned int)cJSON_GetArraySize(diddoc->keyagreement.vm);
            break;
        case VM_PURPOSE_CAPABILITY_INVOCATION:
            if ((diddoc->ci.vm) && cJSON_IsArray(diddoc->ci.vm))
                return  (unsigned int)cJSON_GetArraySize(diddoc->ci.vm);
            break;
        case VM_PURPOSE_CAPABILITY_DELEGATION:
            if ((diddoc->cd.vm) && cJSON_IsArray(diddoc->cd.vm))
                return  (unsigned int)cJSON_GetArraySize(diddoc->cd.vm);
            break;
        case VM_PURPOSE_PUBLIC_KEY:
            if ((diddoc->publickey.vm) && cJSON_IsArray(diddoc->publickey.vm))
                return  (unsigned int)cJSON_GetArraySize(diddoc->publickey.vm);
            break;                                                                                  
        default:
            return 0;
    }

    return 0;    
}

void iotex_verification_method_info_destroy(VerificationMethod_Info *info)
{
    if (NULL == info)
        return;

    if (info->id)
        free(info->id);
    
    if (info->pk_u.multibase)
        free(info->pk_u.multibase);

    free(info);
}

enum VerificationMethod_TypeValue iotex_verification_method_type_get(char *value)
{
    if (NULL == value)
        return VMTypeNone;

    if (0 == strcmp(value, IOTEX_VERIFICATION_METHOD_TYPE_VALUE_JSONWEBKEY2020))
        return JsonWebKey2020;
    else if (0 == strcmp(value, IOTEX_VERIFICATION_METHOD_TYPE_VALUE_ECDSASECP256K1VERIFICATIONKEY2019))
        return EcdsaSecp256k1VerificationKey2019;
    else if (0 == strcmp(value, IOTEX_VERIFICATION_METHOD_TYPE_VALUE_ED25519VEIFICATIONKEY2018))
        return Ed25519VerificationKey2018;
    else if (0 == strcmp(value, IOTEX_VERIFICATION_METHOD_TYPE_VALUE_BLS12381G1KEY2020))
        return Bls12381G1Key2020;
    else if (0 == strcmp(value, IOTEX_VERIFICATION_METHOD_TYPE_VALUE_BLS12381G2KEY2020))
        return Bls12381G2Key2020;
    else if (0 == strcmp(value, IOTEX_VERIFICATION_METHOD_TYPE_VALUE_PGPVERIFICATIONKEY2021))
        return PgpVerificationKey2021;
    else if (0 == strcmp(value, IOTEX_VERIFICATION_METHOD_TYPE_VALUE_RSAVERIFICATIONKEY2018))
        return RsaVerificationKey2018;

    return VMTypeNone;
}

static VerificationMethod_Info *_diddoc_verification_method_get_info(cJSON *vm_item, enum VerificationMethod_Purpose purpose)
{
    if (NULL == vm_item)
        return NULL;

    VerificationMethod_Info *info = malloc(sizeof(VerificationMethod_Info));
    if (NULL == info)
        return NULL;

    cJSON *id_item = cJSON_GetObjectItem(vm_item, "id");
    if (NULL == id_item)
        goto exit;

    if (cJSON_IsString(id_item)) {
        info->id = calloc(strlen(id_item->valuestring) + 1, sizeof(char));
        strcpy(info->id, id_item->valuestring);
    } else
        goto exit;

    info->purpose = purpose;

    cJSON *type_item = cJSON_GetObjectItem(vm_item, "type");
    if (NULL == type_item)
        goto exit;
    if (cJSON_IsString(type_item)) 
        info->type = iotex_verification_method_type_get(type_item->valuestring);
    else
        goto exit;        

    cJSON *jwk_item = cJSON_GetObjectItem(vm_item, "publicKeyJwk");
    if (jwk_item) {
        info->pk_u.jwk = iotex_jwk_get_jwk_from_json_value((void *)jwk_item);
        if (NULL == info->pk_u.jwk)
            goto exit;

        info->pubkey_type = VERIFICATION_METHOD_PUBLIC_KEY_TYPE_JWK;

        return info;
    }

    cJSON *multibase_item = cJSON_GetObjectItem(vm_item, "publicKeyMultibase");
    if (multibase_item) {

        if (!cJSON_IsString(multibase_item))
            goto exit;

        info->pk_u.multibase = calloc(strlen(multibase_item->valuestring) + 1, sizeof(char));
        if (NULL == info->pk_u.multibase)
            goto exit;

        strcpy(info->pk_u.multibase, multibase_item->valuestring);

        info->pubkey_type = VERIFICATION_METHOD_PUBLIC_KEY_TYPE_MULTIBASE;

        return info;
    }

    cJSON *base58_item = cJSON_GetObjectItem(vm_item, "publicKeyBase58");
    if (base58_item) {

        if (!cJSON_IsString(base58_item))
            goto exit;

        info->pk_u.base58 = calloc(strlen(base58_item->valuestring) + 1, sizeof(char));
        if (NULL == info->pk_u.base58)
            goto exit;

        strcpy(info->pk_u.base58, base58_item->valuestring);

        info->pubkey_type = VERIFICATION_METHOD_PUBLIC_KEY_TYPE_BASE58;

        return info;
    }    

exit:
    iotex_verification_method_info_destroy(info);

    return NULL;
}

static VerificationMethod_Map _diddoc_find_vm_map_by_kid(DIDDoc_VerificationMethod *vm, char *kid)
{
    if (NULL == kid || NULL == vm)
        return (VerificationMethod_Map)NULL;

    if (vm->type != VM_TYPE_MAP)
        return (VerificationMethod_Map)NULL;

    if (NULL == vm->vm)
        return (VerificationMethod_Map)NULL;

    if (!cJSON_IsArray(vm->vm))
        return (VerificationMethod_Map)NULL;

    unsigned int item_num = cJSON_GetArraySize(vm->vm);
    if (!item_num)
        return (VerificationMethod_Map)NULL;

    cJSON *item = NULL, *id_item = NULL;
    for (int i = 0; i < item_num; i++) {
        
        item = cJSON_GetArrayItem(vm->vm, i);
        id_item = cJSON_GetObjectItem(item, "id");
        if (id_item && cJSON_IsString(id_item)) {
            if (strcmp(id_item->valuestring, kid))
                continue;

            return (VerificationMethod_Map)item;
        } else
            continue;
    }

    return NULL;
}

static VerificationMethod_Info *_diddoc_verification_method_info_get(DIDDoc *diddoc, DIDDoc_VerificationMethod *vm, enum VerificationMethod_Purpose purpose, unsigned int idx)
{
    if (NULL == diddoc || NULL == vm)
        return NULL;

    if (NULL == vm->vm)
        return NULL;

    if (!cJSON_IsArray(vm->vm))
        return NULL;

    if (vm->type == VM_TYPE_MAP) 
        return _diddoc_verification_method_get_info(cJSON_GetArrayItem(vm->vm, idx), purpose);        
    
    if (vm->type == VM_TYPE_DIDURL) {

        cJSON *item = cJSON_GetArrayItem(vm->vm, idx);
        if (item && cJSON_IsString(item)) {
            VerificationMethod_Map map = _diddoc_find_vm_map_by_kid(&diddoc->vm, item->valuestring);
            if (NULL == map)
                return NULL;
            
            return _diddoc_verification_method_get_info(map, purpose);
        }
    }

    return NULL;
}

VerificationMethod_Info *iotex_diddoc_verification_method_get(DIDDoc *diddoc, enum VerificationMethod_Purpose purpose, unsigned int idx)         
{
    if (NULL == diddoc)
        return NULL;

    unsigned int vm_num = iotex_diddoc_verification_method_get_num(diddoc, purpose);
    if (idx >= vm_num)
        return NULL;

    DIDDoc_VerificationMethod *vm = NULL;
    switch (purpose) {
        case VM_PURPOSE_VERIFICATION_METHOD:            
            vm = &diddoc->vm;
            break;
        case VM_PURPOSE_AUTHENTICATION:
            vm = &diddoc->auth;
            break;
        case VM_PURPOSE_ASSERTION_METHOD:
            vm = &diddoc->assertion;
            break;
        case VM_PURPOSE_KEY_AGREEMENT:
            vm = &diddoc->keyagreement;
            break;
        case VM_PURPOSE_CAPABILITY_INVOCATION:
            vm = &diddoc->ci;
            break;
        case VM_PURPOSE_CAPABILITY_DELEGATION:
            vm = &diddoc->cd;
            break;
        case VM_PURPOSE_PUBLIC_KEY:
            vm = &diddoc->publickey;
            break;                                                                                  
        default:
            return NULL;
    }        

    return _diddoc_verification_method_info_get(diddoc, vm, purpose, idx);
}




