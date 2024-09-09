#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/jose/jws.h"
#include "include/jose/jwk.h"
#include "include/server/crypto.h"
#include "include/utils/baseX/base64.h"

struct _jws_general_json_serialize_info 
{
    char  *base64url_payload;

    jws_handle_t jws_json_handle;

    cJSON *signatures;
};

typedef struct _jws_general_json_serialize_info *_JWSGeneralJsonSerializeInfo_t;

static struct _jws_general_json_serialize_info g_jws_info = {0};

static void _jws_general_json_serizlize_info_init(void)
{
    if (g_jws_info.base64url_payload)
        free(g_jws_info.base64url_payload);

    g_jws_info.base64url_payload = NULL;

    if (g_jws_info.signatures)
        cJSON_Delete(g_jws_info.signatures);

    g_jws_info.signatures = NULL;        
}

static bool _jws_general_json_serizlize_handle_check(jws_handle_t handle)
{
    return g_jws_info.jws_json_handle == handle ? true : false;
}

static char *_jws_protectedheader_encode(enum JWAlogrithm alg, char *typ, bool format)
{
    char *protectedheader_str = NULL, *base64url_protectedheader = NULL;

    cJSON *protectedheader = cJSON_CreateObject();

    if (typ)
        cJSON_AddStringToObject(protectedheader, "typ", typ);

    switch (alg) {
        case ES256:
            cJSON_AddStringToObject(protectedheader, "alg", "ES256");
            break;
        default:
            goto exit;
    }

    if (format)
        protectedheader_str = cJSON_Print(protectedheader);
    else
        protectedheader_str = cJSON_PrintUnformatted(protectedheader);

    if (protectedheader_str) {
        base64url_protectedheader = base64_encode_automatic( protectedheader_str, strlen(protectedheader_str) );

        free(protectedheader_str);
        protectedheader_str = NULL;
    }

exit:    
    cJSON_Delete(protectedheader);

    return base64url_protectedheader;
}

static void *_jws_header_build(char *kid)
{
    if (NULL == kid)
        return NULL;

    cJSON *header = cJSON_CreateObject();
    cJSON_AddStringToObject(header, "kid", kid);

    return (void *)header;
}

char *iotex_jws_compact_serialize(enum JWAlogrithm alg, char *plaintext, size_t plaintext_size, JWK *jwk)
{
    char *jws_compact_serialize = NULL;

    if (NULL == plaintext || 0 == plaintext_size)
        return NULL;

    if (NULL == jwk)
        return NULL;

    char *protectedheader = _jws_protectedheader_encode(alg, NULL, false);
    if (NULL == protectedheader)
        return NULL;
    
    char *base64url_payload = base64_encode_automatic(plaintext, plaintext_size);
    if (NULL == base64url_payload) {
        free(protectedheader);
        return NULL;
    }
  
    uint8_t hash[32];
    size_t  hash_size = 0;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    
    psa_hash_setup(&operation, PSA_ALG_SHA_256);
    psa_hash_update(&operation, (const uint8_t *)protectedheader, strlen(protectedheader));
    psa_hash_update(&operation, (const uint8_t *)".", 1);
    psa_hash_update(&operation, (const uint8_t *)base64url_payload, strlen(base64url_payload));
    psa_hash_finish(&operation, hash, sizeof(hash), &hash_size);
    
    uint8_t signature[64];
    size_t  signature_length;
    psa_status_t status = psa_sign_hash(jwk->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_size, signature, sizeof(signature), &signature_length);
    if (PSA_SUCCESS != status)
        goto exit_2;

    char *base64url_signature = base64_encode_automatic((const char *)signature, signature_length);
    if (NULL == base64url_signature)
        goto exit_2;
    
    size_t jws_compact_serialize_size = strlen(protectedheader) + 1 + strlen(base64url_payload) + 1 + strlen(base64url_signature) + 1;
    jws_compact_serialize = realloc(protectedheader, jws_compact_serialize_size);
    if (jws_compact_serialize) 
        snprintf(jws_compact_serialize + strlen(jws_compact_serialize), jws_compact_serialize_size - strlen(jws_compact_serialize), ".%s.%s", base64url_payload, base64url_signature);
    
// exit_1:
    if (base64url_signature)
        free(base64url_signature);
exit_2:
    if (base64url_payload)
        free(base64url_payload);

    return jws_compact_serialize;             
}

jws_handle_t iotex_jws_general_json_serialize_init(char *plaintext, size_t plaintext_size)
{
    if (NULL == plaintext || 0 == plaintext_size)
        return (jws_handle_t) 0;

    _jws_general_json_serizlize_info_init();

    g_jws_info.base64url_payload = base64_encode_automatic(plaintext, plaintext_size);
    if (NULL == g_jws_info.base64url_payload)
        return (jws_handle_t) 0;

    g_jws_info.signatures = cJSON_CreateArray();
    if (NULL == g_jws_info.signatures) {
        free(g_jws_info.base64url_payload);
        g_jws_info.base64url_payload = NULL;

        return (jws_handle_t) 0;
    }
    
    return ++g_jws_info.jws_json_handle;
}

jose_status_t iotex_jws_general_json_serialize_update(jws_handle_t handle, enum JWAlogrithm alg, char *kid, JWK *jwk)
{
    if (!_jws_general_json_serizlize_handle_check(handle))
        return JOSE_ERROR_INVALID_HANDLE;

    if (NULL == g_jws_info.base64url_payload)
        return JOSE_ERROR_BAD_STATE;

    if (NULL == jwk)
        return JOSE_ERROR_INVALID_ARGUMENT;        

    char *protectedheader = _jws_protectedheader_encode(alg, NULL, false);
    if (NULL == protectedheader)
        return JOSE_ERROR_INSUFFICIENT_MEMORY;

    uint8_t hash[32];
    size_t  hash_size = 0;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_hash_setup(&operation, PSA_ALG_SHA_256);

    psa_hash_update(&operation, (const uint8_t *)protectedheader, strlen(protectedheader));
    psa_hash_update(&operation, (const uint8_t *)".", 1);
    psa_hash_update(&operation,(const uint8_t *)g_jws_info.base64url_payload, strlen(g_jws_info.base64url_payload));
    psa_hash_finish(&operation, hash, sizeof(hash), &hash_size);
    
    uint8_t signature[64];
    size_t  signature_length;
    psa_status_t status = psa_sign_hash(jwk->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_size, signature, sizeof(signature), &signature_length);
    if (PSA_SUCCESS != status) {
        free(protectedheader);
        return JOSE_ERROR_INTERNAL_COMPUTE;
    }

    char *base64url_signature = base64_encode_automatic((const char *)signature, signature_length);
    if (NULL == base64url_signature) {
        free(protectedheader);
        return JOSE_ERROR_INTERNAL_COMPUTE;        
    }

    cJSON *signature_item = cJSON_CreateObject();
    cJSON_AddStringToObject(signature_item, "protected", protectedheader);

    if (kid) 
        cJSON_AddItemToObject(signature_item, "header", (cJSON *)_jws_header_build(kid));

    cJSON_AddStringToObject(signature_item, "signature", base64url_signature);          
    cJSON_AddItemToArray(g_jws_info.signatures, signature_item);

    if (base64url_signature)
        free(base64url_signature);
    
    if (protectedheader)
        free(protectedheader);

    return JOSE_SUCCESS;         
}

char *iotex_jws_general_json_serialize_finish(jws_handle_t handle, bool format)
{
    char *jws_general_json = NULL;

    if (!_jws_general_json_serizlize_handle_check(handle))
        return NULL;

    if (NULL == g_jws_info.base64url_payload)
        return NULL;

    cJSON *jws_general_json_object = cJSON_CreateObject();
    cJSON_AddStringToObject(jws_general_json_object, "payload", g_jws_info.base64url_payload);
    cJSON_AddItemToObject(jws_general_json_object, "signatures", g_jws_info.signatures);

    if (format)
        jws_general_json = cJSON_Print(jws_general_json_object);
    else
        jws_general_json = cJSON_PrintUnformatted(jws_general_json_object);

    cJSON_Delete(jws_general_json_object);
    g_jws_info.signatures = NULL;

    _jws_general_json_serizlize_info_init();

    return jws_general_json;
}

char *iotex_jws_flattened_json_serialize(enum JWAlogrithm alg, char *plaintext, size_t plaintext_size, char *kid, enum JWS_USAGE usage, JWK *jwk, bool format)
{
    char *jws_flattened_serialize = NULL;
    char *typ = NULL;

    if (NULL == plaintext || 0 == plaintext_size)
        return NULL;

    if (NULL == jwk)
        return NULL;

    if (usage == JWS_USAGE_DIDCOMM)
        typ = JOSE_HEADER_TYPE_SIGN_TYPE;

    char *protectedheader = _jws_protectedheader_encode(alg, typ, false);
    if (NULL == protectedheader)
        return NULL;
    
    char *base64url_payload = base64_encode_automatic(plaintext, plaintext_size);
    if (NULL == base64url_payload)
        goto exit_3;

    uint8_t hash[32];
    size_t  hash_size = 0;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_hash_setup(&operation, PSA_ALG_SHA_256);

    psa_hash_update(&operation, (const uint8_t *)protectedheader, strlen(protectedheader));
    psa_hash_update(&operation, (const uint8_t *)".", 1);
    psa_hash_update(&operation, (const uint8_t *)base64url_payload, strlen(base64url_payload));
    psa_hash_finish(&operation, hash, sizeof(hash), &hash_size);
    
    uint8_t signature[64];
    size_t  signature_length;
    psa_status_t status = psa_sign_hash(jwk->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_size, signature, sizeof(signature), &signature_length);
    if (PSA_SUCCESS != status)
        goto exit_2;

    char *base64url_signature = base64_encode_automatic((const char *)signature, signature_length);
    if (NULL == base64url_signature)
        goto exit_2;

    cJSON *jws_json_object = cJSON_CreateObject();
    if (NULL == jws_json_object)
        goto exit_1;

    cJSON_AddStringToObject(jws_json_object, "payload", base64url_payload);     
    cJSON_AddStringToObject(jws_json_object, "protected", protectedheader);
    
    if (kid) 
        cJSON_AddItemToObject(jws_json_object, "header", (cJSON *)_jws_header_build(kid));

    cJSON_AddStringToObject(jws_json_object, "signature", base64url_signature);          

    if (format)
        jws_flattened_serialize = cJSON_Print(jws_json_object);
    else
        jws_flattened_serialize = cJSON_PrintUnformatted(jws_json_object);

    cJSON_Delete(jws_json_object);

exit_1:
    if (base64url_signature)
        free(base64url_signature);
exit_2:
    if (base64url_payload)
        free(base64url_payload);
exit_3:
    if (protectedheader)
        free(protectedheader);

    return jws_flattened_serialize;  
}

jose_status_t _find_point_position(char *jws, uint32_t *first, uint32_t *second)
{
    uint32_t idx = 0;

    if (NULL == jws)
        return JOSE_ERROR_INVALID_ARGUMENT;

    size_t jws_size = strlen(jws);

    for (int i = 0; i < jws_size; i++) {

        if (jws[i] != '.') 
            continue;

        idx++;

        if (idx == 1 && first)
            *first = i;            

        if (idx == 2 && second)
            *second = i;            
    }

    if (idx != 2) 
        return JOSE_ERROR_INSUFFICIENT_DATA;

    return JOSE_SUCCESS;
}

static bool _is_jws_compact(char *jws)
{
    if (JOSE_SUCCESS != _find_point_position(jws, NULL, NULL))
        return false;

    return true;
}

bool iotex_jws_compact_verify(enum JWAlogrithm alg, char *jws_msg, JWK *jwk)
{
    if (NULL == jws_msg || NULL == jwk)
        return false;

    if (!_is_jws_compact(jws_msg))
        return false;

    uint32_t payload_pos = 0, signature_pos = 0;
    jose_status_t jose_status = _find_point_position(jws_msg, &payload_pos, &signature_pos);
    if (JOSE_SUCCESS != jose_status)
        return false;

    uint8_t hash[32] = {0};
    size_t  hash_size = 0;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    
    psa_hash_setup(&operation, PSA_ALG_SHA_256);
    psa_hash_update(&operation, (const uint8_t *)jws_msg, signature_pos);
    psa_hash_finish(&operation, hash, sizeof(hash), &hash_size);

    size_t signature_size = 0;
    char *signature = base64_decode_automatic(jws_msg + signature_pos + 1, strlen(jws_msg) - signature_pos - 1, &signature_size);
    if (NULL == signature)
        return false;

    psa_status_t psa_status = psa_verify_hash( jwk->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_size, (const uint8_t *)signature, signature_size);

    if (signature)
        free(signature);

    return (PSA_SUCCESS == psa_status) ? true : false;
}

