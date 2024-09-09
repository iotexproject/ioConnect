#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "include/dids/vc/vc.h"
#include "include/utils/cJSON/cJSON.h"

struct _vc_json_serialize_info 
{
    vc_handle_t handle;
    VerifiableCredential *vc;
};

typedef struct _vc_json_serialize_info *VCJsonSerializeInfo_t;

static struct _vc_json_serialize_info g_vc_info = {0};
static char *ProofSuiteType_str[] = { "DataIntegrityProof", "Ed25519Signature2020", "Ed25519Signature2018",
                                        "EcdsaSecp256k1Signature2019", "EcdsaSecp256r1Signature2019", "RsaSignature2018", "JsonWebSignature2020"};
static char *DataIntegrityCryptoSuite_str[] = { "eddsa-2022", "json-eddsa-2022", "ecdsa-2019", "jcs-ecdsa-2019"};                                        

char *iotex_get_proof_suite_type_string(enum ProofSuiteType type)
{
    if (type >= ProofSuiteTypeMax)
        return NULL;

    return ProofSuiteType_str[type];
}

char *iotex_get_data_intergrity_cryptosuite_string(enum DataIntegrityCryptoSuite type)
{
    if (type >= DataIntegrityCryptoSuiteMax)
        return NULL;

    return DataIntegrityCryptoSuite_str[type];
}

vc_handle_t iotex_vc_new(void)
{
    if (g_vc_info.vc)
         iotex_vc_destroy(g_vc_info.handle);

    g_vc_info.vc = malloc(sizeof(VerifiableCredential));
    if (NULL == g_vc_info.vc)
        return (vc_handle_t)0;

    memset(g_vc_info.vc, 0, sizeof(VerifiableCredential));        
    
    return ++g_vc_info.handle;
}

did_status_t iotex_vc_destroy(vc_handle_t handle)
{
    if (handle != g_vc_info.handle)
        return DID_ERROR_INVALID_ARGUMENT;

    if (NULL == g_vc_info.vc)        
        return DID_SUCCESS;

    if (g_vc_info.vc->contests.contexts)
        cJSON_Delete(g_vc_info.vc->contests.contexts);        

    if (g_vc_info.vc->types.typs)
        cJSON_Delete(g_vc_info.vc->types.typs);        

    if (g_vc_info.vc->css.css)
        cJSON_Delete(g_vc_info.vc->css.css);        

    if (g_vc_info.vc->issuer.issuer)
        cJSON_Delete(g_vc_info.vc->issuer.issuer);        

    if (g_vc_info.vc->proofs.proofs)
        cJSON_Delete(g_vc_info.vc->proofs.proofs);        

    if (g_vc_info.vc->status.status)
        cJSON_Delete(g_vc_info.vc->status.status);        

    if (g_vc_info.vc->terms_of_use.termsofuse)
        cJSON_Delete(g_vc_info.vc->terms_of_use.termsofuse);        

    if (g_vc_info.vc->evidences.evidences)
        cJSON_Delete(g_vc_info.vc->evidences.evidences);        

    if (g_vc_info.vc->schemas.schemas)
        cJSON_Delete(g_vc_info.vc->schemas.schemas);        

    if (g_vc_info.vc->refresh_services.rss)
        cJSON_Delete(g_vc_info.vc->refresh_services.rss);        

    if (g_vc_info.vc->property_set)
        cJSON_Delete((cJSON *)g_vc_info.vc->property_set);

    memset(g_vc_info.vc, 0, sizeof(VerifiableCredential));

    free(g_vc_info.vc);
    g_vc_info.vc = NULL;   

    return DID_SUCCESS;      
}

static did_status_t _vc_sub_property_set(cJSON *object, unsigned int subtype, char *name, void *value)
{
    if (NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;

    if ((subtype & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK) && (NULL == name))        
        return DID_ERROR_INVALID_ARGUMENT;

    switch (subtype) {
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID:
            cJSON_AddStringToObject(object, "id", value);
            break;
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE:
            cJSON_AddStringToObject(object, "type", value);
            break;
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_STRING:
            cJSON_AddStringToObject(object, name, value);
            break;
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_NUM:
            cJSON_AddNumberToObject(object, name, *(double *)value);
            break;
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_BOOL:
            cJSON_AddBoolToObject(object, name, *(cJSON_bool *)value);
            break;
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_JSON:
            cJSON_AddItemToObject(object, name, cJSON_Duplicate((cJSON *)value, true));  
            break;                           
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }        

    return DID_SUCCESS;
}

static void * _vc_sub_property_get(cJSON *object, unsigned int subtype, char *name)
{
    void *value = NULL;

    if (NULL == object)
        return NULL;

    if ((subtype & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK) && (NULL == name))        
        return NULL;

    switch (subtype) {
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID: {
                cJSON *id = cJSON_GetObjectItem(object, "id");
                if (NULL == id || !cJSON_IsString(id))
                    break;

                value = calloc(strlen(id->valuestring) + 1, sizeof(char));
                strcpy(value, id->valuestring);                 
                
                break;
        }
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE: {
            cJSON *type = cJSON_GetObjectItem(object, "type");
            if (NULL == type || !cJSON_IsString(type))
                break;
            
            value = calloc(strlen(type->valuestring) + 1, sizeof(char));
            strcpy(value, type->valuestring);             
            break;
        }
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_STRING: {
            cJSON *private_str = cJSON_GetObjectItem(object, name);
            if (NULL == private_str || !cJSON_IsString(private_str))
                break;
            
            value = calloc(strlen(private_str->valuestring) + 1, sizeof(char));
            strcpy(value, private_str->valuestring);                    
            break;
        }
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_NUM: {
            cJSON *private_num = cJSON_GetObjectItem(object, name);
            if (NULL == private_num || !cJSON_IsNumber(private_num))
                break;
            
            value = malloc(sizeof(int));
            *(int *)value = private_num->valueint;                          
            break;
        }
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_BOOL: {
            cJSON *private_bool = cJSON_GetObjectItem(object, name);
            if (NULL == private_bool || !cJSON_IsBool(private_bool))
                break;
            
            value = malloc(sizeof(bool));
            *(int *)value = private_bool->valueint;             
            break;
        }
        case IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_JSON: {
            cJSON *private_json = cJSON_GetObjectItem(object, name);
            if (NULL == private_json || !cJSON_IsObject(private_json))
                break;
              
            value = malloc(sizeof(cJSON *)); 
            value = (void *)cJSON_Duplicate(private_json, cJSON_True);

            break;                                                
        }
        default:
            return NULL;
    }        

    return value;
}

did_status_t iotex_vc_property_set(vc_handle_t handle, unsigned int build_type, char *name, void *value)
{
    did_status_t status = DID_SUCCESS;

    if (g_vc_info.handle != handle || 0 == build_type || NULL == value)
        return DID_ERROR_INVALID_ARGUMENT;

    if (NULL == g_vc_info.vc)        
        return DID_ERROR_BAD_STATE;

    unsigned int main_type = (build_type & IOTEX_VC_BUILD_PROPERTY_MAIN_TYPE_MASK);                
    unsigned int sub_type  = (build_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_MASK);

    if ( main_type < IOTEX_VC_BUILD_PROPERTY_TYPE_MIN || main_type > IOTEX_VC_BUILD_PROPERTY_TYPE_MAX)
        return DID_ERROR_INVALID_ARGUMENT;

    switch (main_type) {
        case IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT:
            
            if (NULL == g_vc_info.vc->contests.contexts) {
                g_vc_info.vc->contests.contexts = cJSON_CreateArray();
            }
        
            cJSON_AddItemToArray(g_vc_info.vc->contests.contexts, cJSON_CreateString(value));            

            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ID:

            if (strlen(value) >= IOTEX_VC_PROPERTY_ID_BUFFER_SIZE)
                return DID_ERROR_BUFFER_TOO_SMALL;

            if (g_vc_info.vc->id[0])
                memset(g_vc_info.vc->id, 0, IOTEX_VC_PROPERTY_ID_BUFFER_SIZE);

            strcpy(g_vc_info.vc->id, value);                
            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_TYPE:

            if (NULL == g_vc_info.vc->types.typs)
                g_vc_info.vc->types.typs = cJSON_CreateArray();

            cJSON_AddItemToArray(g_vc_info.vc->types.typs, cJSON_CreateString(value));  

            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_CS:

            if (NULL == g_vc_info.vc->css.css)
                g_vc_info.vc->css.css = cJSON_CreateArray();

            cJSON_AddItemToArray(g_vc_info.vc->css.css, (cJSON *)value);  

            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ISSUER_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;         

            if (NULL == g_vc_info.vc->issuer.issuer)
                g_vc_info.vc->issuer.issuer = cJSON_CreateObject();

            status = _vc_sub_property_set(g_vc_info.vc->issuer.issuer, sub_type, name, value);                
            if (DID_SUCCESS != status)
                return status;

            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER_DATE:

            if (strlen(value) >= IOTEX_VC_PROPERTY_ISSUANCE_DATE_BUFFER_SIZE)
                return DID_ERROR_BUFFER_TOO_SMALL;

            if (g_vc_info.vc->issuance_date[0])
                memset(g_vc_info.vc->issuance_date, 0, IOTEX_VC_PROPERTY_ISSUANCE_DATE_BUFFER_SIZE);

            strcpy(g_vc_info.vc->issuance_date, value);                
            break;                        
        case IOTEX_VC_BUILD_PROPERTY_TYPE_PROOF:

            if (NULL == g_vc_info.vc->proofs.proofs)
                g_vc_info.vc->proofs.proofs = cJSON_CreateArray();

            cJSON_AddItemToArray(g_vc_info.vc->proofs.proofs, (cJSON *)value);  

            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_STATUS:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_STATUS_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;        

            if (NULL == g_vc_info.vc->status.status)
                g_vc_info.vc->status.status = cJSON_CreateObject();

            status = _vc_sub_property_set(g_vc_info.vc->status.status, sub_type, name, value);                
            if (DID_SUCCESS != status)
                return status;

            break;  
        case IOTEX_VC_BUILD_PROPERTY_TYPE_TERMOFUSE:

            if (NULL == g_vc_info.vc->terms_of_use.termsofuse)
                g_vc_info.vc->terms_of_use.termsofuse = cJSON_CreateArray();

            cJSON_AddItemToArray(g_vc_info.vc->terms_of_use.termsofuse, (cJSON *)value); 

            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_EVIDENCE:

            if (NULL == g_vc_info.vc->evidences.evidences)
                g_vc_info.vc->evidences.evidences = cJSON_CreateArray();

            cJSON_AddItemToArray(g_vc_info.vc->evidences.evidences, (cJSON *)value);                

            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_SCHEMA:
        
            if (NULL == g_vc_info.vc->schemas.schemas)
                g_vc_info.vc->schemas.schemas = cJSON_CreateArray();

            cJSON_AddItemToArray(g_vc_info.vc->schemas.schemas, (cJSON *)value);                

            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_RS:

            if (NULL == g_vc_info.vc->refresh_services.rss)
                g_vc_info.vc->refresh_services.rss = cJSON_CreateArray();

            cJSON_AddItemToArray(g_vc_info.vc->schemas.schemas, (cJSON *)value); 

            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_EXP:

            if (strlen(value) >= IOTEX_VC_PROPERTY_EXP_DATE_BUFFER_SIZE)
                return DID_ERROR_BUFFER_TOO_SMALL;

            if (g_vc_info.vc->exp_date[0])
                memset(g_vc_info.vc->exp_date, 0, IOTEX_VC_PROPERTY_EXP_DATE_BUFFER_SIZE);

            strcpy(g_vc_info.vc->exp_date, value); 

            break;                      
        case IOTEX_VC_BUILD_PROPERTY_TYPE_PROPERTY:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PROPERTY_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;

            if (NULL == g_vc_info.vc->property_set)
                g_vc_info.vc->property_set = cJSON_CreateObject();

            status = _vc_sub_property_set(g_vc_info.vc->property_set, sub_type, name, value);                
            if (DID_SUCCESS != status)
                return status;

            break;                                                   
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }

    return DID_SUCCESS;        
}

void * iotex_vc_property_get(char *vc_serialize, unsigned int build_type, char *name, int idx)
{
    int array_size = 0;
    void *value = NULL;

    if ( idx < 0)
        return NULL;

    if (NULL == vc_serialize || 0 == build_type)
        return NULL;

    unsigned int main_type = (build_type & IOTEX_VC_BUILD_PROPERTY_MAIN_TYPE_MASK);                
    unsigned int sub_type  = (build_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_MASK);

    if ( main_type < IOTEX_VC_BUILD_PROPERTY_TYPE_MIN || main_type > IOTEX_VC_BUILD_PROPERTY_TYPE_MAX)
        return NULL;

    cJSON *vc_root = cJSON_Parse(vc_serialize);
    if (NULL == vc_root)
        return NULL;
    
    switch (main_type) {
        case IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT:
            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ID:
            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_TYPE:
            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_CS: {
            cJSON *cs_items = cJSON_GetObjectItem(vc_root, "credentialSubject");
            if (NULL == cs_items || !cJSON_IsArray(cs_items))
                goto exit;
            
            array_size = cJSON_GetArraySize(cs_items);
            if (0 == array_size || idx >= array_size )
                goto exit;
            
            cJSON *cs_item = cJSON_GetArrayItem(cs_items, idx);
            if (NULL == cs_item || !cJSON_IsObject(cs_item))
                goto exit;
            
            value = _vc_sub_property_get(cs_item, sub_type, name);
            break;            
        }
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER:
            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER_DATE:
            break;                        
        case IOTEX_VC_BUILD_PROPERTY_TYPE_PROOF:
            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_STATUS:
            break;  
        case IOTEX_VC_BUILD_PROPERTY_TYPE_TERMOFUSE:
            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_EVIDENCE:
            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_SCHEMA:
            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_RS:
            break;
        case IOTEX_VC_BUILD_PROPERTY_TYPE_EXP:
            break;                      
        case IOTEX_VC_BUILD_PROPERTY_TYPE_PROPERTY:
            break;                                                   
        default:
            break;
    }

exit:
    if (vc_root)
        cJSON_Delete(vc_root);

    return value;        
}

property_handle_t iotex_vc_sub_property_new(void)
{
    return cJSON_CreateObject();
}

did_status_t iotex_vc_sub_property_destroy(property_handle_t handle)
{
    if (NULL == handle)
        return DID_ERROR_INVALID_ARGUMENT;

    cJSON_Delete(handle);

    return DID_SUCCESS;        
}

did_status_t iotex_vc_sub_property_set(property_handle_t handle, unsigned int build_type, char *name, void *value)
{
    if (NULL == value || NULL == handle)
        return DID_ERROR_INVALID_ARGUMENT;

    unsigned int main_type = (build_type & IOTEX_VC_BUILD_PROPERTY_MAIN_TYPE_MASK);                
    unsigned int sub_type  = (build_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_MASK);

    if ( main_type < IOTEX_VC_BUILD_PROPERTY_TYPE_MIN || main_type > IOTEX_VC_BUILD_PROPERTY_TYPE_MAX)
        return DID_ERROR_INVALID_ARGUMENT;

    switch (main_type) {
        case IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT:
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ID:              
        case IOTEX_VC_BUILD_PROPERTY_TYPE_TYPE:
        case IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER:
        case IOTEX_VC_BUILD_PROPERTY_TYPE_STATUS:
        case IOTEX_VC_BUILD_PROPERTY_TYPE_EXP:
        case IOTEX_VC_BUILD_PROPERTY_TYPE_PROPERTY:                                
            return DID_ERROR_INVALID_ARGUMENT;

        case IOTEX_VC_BUILD_PROPERTY_TYPE_CS:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_CS_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;
                                     
            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_PROOF:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PROOF_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;

            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_TERMOFUSE:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TERMOFUSE_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;

            break;            
        case IOTEX_VC_BUILD_PROPERTY_TYPE_EVIDENCE:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_EVIDENCE_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;

            break;              
        case IOTEX_VC_BUILD_PROPERTY_TYPE_SCHEMA:
        
            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_SCHEMA_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;

            break;  
        case IOTEX_VC_BUILD_PROPERTY_TYPE_RS:

            if (0 == (sub_type & IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_RS_VALID_MASK))
                return DID_ERROR_INVALID_ARGUMENT;

            break;                                             
        default:
            return DID_ERROR_INVALID_ARGUMENT;
    }       

    return _vc_sub_property_set(handle, sub_type, name, value);
}

char *iotex_vc_serialize(vc_handle_t handle, bool format)
{
    char *vc_serialize = NULL;

    if (g_vc_info.handle != handle)
        return NULL;

    if (NULL == g_vc_info.vc)        
        return NULL;

    cJSON * vc_serialize_obj = cJSON_CreateObject();
    if (NULL == vc_serialize_obj)
        return NULL;

    if (g_vc_info.vc->contests.contexts) {
        cJSON_AddItemToObject(vc_serialize_obj, "@context", cJSON_Duplicate(g_vc_info.vc->contests.contexts, true));       // TODO:
    }

    if (g_vc_info.vc->id[0]) {
        cJSON_AddStringToObject(vc_serialize_obj, "id", g_vc_info.vc->id);
    }        

    if (g_vc_info.vc->types.typs)
        cJSON_AddItemToObject(vc_serialize_obj, "type", cJSON_Duplicate(g_vc_info.vc->types.typs, true));        

    if (g_vc_info.vc->css.css)
        cJSON_AddItemToObject(vc_serialize_obj, "credentialSubject", cJSON_Duplicate(g_vc_info.vc->css.css, true));

    if (g_vc_info.vc->issuer.issuer)
        cJSON_AddItemToObject(vc_serialize_obj, "issuer", cJSON_Duplicate(g_vc_info.vc->issuer.issuer, true));             // TODO:

    if (g_vc_info.vc->issuance_date[0])
        cJSON_AddStringToObject(vc_serialize_obj, "issuanceDate", g_vc_info.vc->issuance_date);         

    if (g_vc_info.vc->proofs.proofs)
        cJSON_AddItemToObject(vc_serialize_obj, "proof", cJSON_Duplicate(g_vc_info.vc->proofs.proofs, true));              // TODO:         

    if (g_vc_info.vc->exp_date[0])
        cJSON_AddStringToObject(vc_serialize_obj, "expirationDate", g_vc_info.vc->id);

    if (g_vc_info.vc->status.status)
        cJSON_AddItemToObject(vc_serialize_obj, "credentialStatus", cJSON_Duplicate(g_vc_info.vc->status.status, true));

    if (g_vc_info.vc->terms_of_use.termsofuse)
        cJSON_AddItemToObject(vc_serialize_obj, "termsOfUse", cJSON_Duplicate(g_vc_info.vc->terms_of_use.termsofuse, true));

    // https://www.w3.org/TR/2022/REC-vc-data-model-20220303/ Dont include this property.
    // if (g_vc_info.vc->schemas.schemas)
    //     cJSON_AddItemToObject(vc_serialize_obj, "termsOfUse", g_vc_info.vc->terms_of_use.termsofuse);

    if (g_vc_info.vc->refresh_services.rss)
        cJSON_AddItemToObject(vc_serialize_obj, "refreshService", cJSON_Duplicate(g_vc_info.vc->refresh_services.rss, true));

    if (g_vc_info.vc->property_set)
        cJSON_AddItemToObject(vc_serialize_obj, "Property_set", cJSON_Duplicate(g_vc_info.vc->property_set, true));

    if (format)
        vc_serialize = cJSON_Print(vc_serialize_obj);
    else        
        vc_serialize = cJSON_PrintUnformatted(vc_serialize_obj);
    
    cJSON_Delete(vc_serialize_obj);

    return vc_serialize;        
}   

/*
cJSON *root = cJSON_Parse(json_string);  // 假设这是你得到的 cJSON 结构体
if (root != NULL && root->type == cJSON_Object) {
    cJSON *child = root->child;  // 获取第一个子项
    while (child != NULL) {
        const char *key = child->string;  // 获取子项的 key 值
        cJSON *value = child->value;  // 获取子项的 value

        // 根据子项的类型进行处理，例如：
        if (value->type == cJSON_String) {
            const char *str_value = value->valuestring;  // 如果是字符串类型，获取其值
            // 处理字符串类型的值
        } else if (value->type == cJSON_Number) {
            double num_value = value->valuedouble;  // 如果是数字类型，获取其值
            // 处理数字类型的值
        }
        // 其他类型的处理...

        child = child->next;  // 获取下一个子项
    }
}
cJSON_Delete(root);  // 释放 cJSON 结构体的内存
*/
