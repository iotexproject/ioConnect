#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/jose/jws.h"
#include "include/jose/jwk.h"
#include "include/jose/jwt.h"

#include "include/utils/cJSON/cJSON.h"
#include "include/utils/baseX/base64.h"

JWTClaim_handle iotex_jwt_claim_new(void)
{
    JWTClaim_handle handle = malloc(sizeof(struct _JWTClaim_handle));
    if (NULL == handle)
        return NULL;

    memset(handle, 0, sizeof(struct _JWTClaim_handle));

    handle->claim = cJSON_CreateObject();

    return handle;
}

void iotex_jwt_claim_destroy(JWTClaim_handle handle)
{
    if (NULL == handle)
        return;

    if (handle->claim)
        cJSON_Delete(handle->claim);

    free(handle);
}

jose_status_t iotex_jwt_claim_set_value(JWTClaim_handle handle, enum JWTClaimType type, char *name, void *value)
{
    if (NULL == value || NULL == handle)
        return JOSE_ERROR_INVALID_ARGUMENT;
        
    if ((type == JWT_CLAIM_TYPE_PRIVATE_STRING || type == JWT_CLAIM_TYPE_PRIVATE_NUM || type == JWT_CLAIM_TYPE_PRIVATE_BOOL || type == JWT_CLAIM_TYPE_PRIVATE_JSON) && NULL == name)
        return JOSE_ERROR_INVALID_ARGUMENT;

    if (NULL == handle->claim)
        handle->claim = cJSON_CreateObject();

    switch (type) {
        case JWT_CLAIM_TYPE_ISS:
            cJSON_AddStringToObject(handle->claim, "iss", (char *)value);
            break;
        case JWT_CLAIM_TYPE_SUB:
            cJSON_AddStringToObject(handle->claim, "sub", (char *)value);
            break;
        case JWT_CLAIM_TYPE_AUD:
            cJSON_AddStringToObject(handle->claim, "aud", (char *)value);
            break;
        case JWT_CLAIM_TYPE_EXP:
            cJSON_AddNumberToObject(handle->claim, "exp", *(time_t *)value);
            break;
        case JWT_CLAIM_TYPE_NBF:
            cJSON_AddNumberToObject(handle->claim, "nbf", *(time_t *)value);
            break;
        case JWT_CLAIM_TYPE_IAT:
            cJSON_AddNumberToObject(handle->claim, "iat", *(time_t *)value);
            break;
        case JWT_CLAIM_TYPE_PRIVATE_STRING:
            cJSON_AddStringToObject(handle->claim, name, (char *)value);
            break;
        case JWT_CLAIM_TYPE_PRIVATE_NUM:
            cJSON_AddNumberToObject(handle->claim, name, *(double *)value);
            break;
        case JWT_CLAIM_TYPE_PRIVATE_BOOL:
            cJSON_AddBoolToObject(handle->claim, name, *(cJSON_bool *)value);
            break;
        case JWT_CLAIM_TYPE_PRIVATE_JSON:
            cJSON_AddItemToObject(handle->claim, name, cJSON_Duplicate((cJSON *)value, true));            
            break;
        default:
            return JOSE_ERROR_INVALID_ARGUMENT;            
    }

    return JOSE_SUCCESS;
}

void * iotex_jwt_claim_get_value(char *jwt_serialize, enum JWTType jwt_type, enum JWTClaimType type, char *name)
{
    void *value = NULL;

    if (NULL == jwt_serialize)
        return NULL;

    if ((type == JWT_CLAIM_TYPE_PRIVATE_STRING || type == JWT_CLAIM_TYPE_PRIVATE_NUM || type == JWT_CLAIM_TYPE_PRIVATE_BOOL || type == JWT_CLAIM_TYPE_PRIVATE_JSON) && NULL == name)
        return NULL;

    uint32_t payload_pos = 0, signature_pos = 0;
    jose_status_t jose_status = _find_point_position(jwt_serialize, &payload_pos, &signature_pos);
    if (JOSE_SUCCESS != jose_status)
        return NULL;

    size_t out_len = 0;
    char *payload = base64_decode_automatic(jwt_serialize + payload_pos + 1, signature_pos - payload_pos - 1, &out_len);
    if (NULL == payload)
        return NULL;

    cJSON *payload_root = cJSON_Parse(payload);
    if (NULL == payload_root)
        goto exit_1;
 
    switch (type) {
        case JWT_CLAIM_TYPE_ISS: {
            cJSON *iss = cJSON_GetObjectItem(payload_root, "iss");
            if (NULL == iss || !cJSON_IsString(iss))
                goto exit_2;
            
            value = calloc(strlen(iss->valuestring) + 1, sizeof(char));
            strcpy(value, iss->valuestring);
            break;
        }
        case JWT_CLAIM_TYPE_SUB: {
            cJSON *sub = cJSON_GetObjectItem(payload_root, "sub");
            if (NULL == sub || !cJSON_IsString(sub))
                goto exit_2;
            
            value = calloc(strlen(sub->valuestring) + 1, sizeof(char));
            strcpy(value, sub->valuestring);            
            break;
        }
        case JWT_CLAIM_TYPE_AUD: {
            cJSON *aud = cJSON_GetObjectItem(payload_root, "aud");
            if (NULL == aud || !cJSON_IsString(aud))
                goto exit_2;
            
            value = calloc(strlen(aud->valuestring) + 1, sizeof(char));
            strcpy(value, aud->valuestring);             
            break;
        }
        case JWT_CLAIM_TYPE_EXP: {
            cJSON *exp = cJSON_GetObjectItem(payload_root, "exp");
            if (NULL == exp || !cJSON_IsNumber(exp))
                goto exit_2;
            
            value = malloc(sizeof(int));
            *(int *)value = exp->valueint;
            break;
        }
        case JWT_CLAIM_TYPE_NBF: {
            cJSON *nbf = cJSON_GetObjectItem(payload_root, "nbf");
            if (NULL == nbf || !cJSON_IsNumber(nbf))
                goto exit_2;
            
            value = malloc(sizeof(int));
            *(int *)value = nbf->valueint;            
            break;
        }
        case JWT_CLAIM_TYPE_IAT: {
            cJSON *iat = cJSON_GetObjectItem(payload_root, "iat");
            if (NULL == iat || !cJSON_IsNumber(iat))
                goto exit_2;
            
            value = malloc(sizeof(int));
            *(int *)value = iat->valueint;            
            break;
        }
        case JWT_CLAIM_TYPE_PRIVATE_STRING: {
            cJSON *private_str = cJSON_GetObjectItem(payload_root, name);
            if (NULL == private_str || !cJSON_IsString(private_str))
                goto exit_2;
            
            value = calloc(strlen(private_str->valuestring) + 1, sizeof(char));
            strcpy(value, private_str->valuestring);             
            break;
        }
        case JWT_CLAIM_TYPE_PRIVATE_NUM: {
            cJSON *private_num = cJSON_GetObjectItem(payload_root, name);
            if (NULL == private_num || !cJSON_IsNumber(private_num))
                goto exit_2;
            
            value = malloc(sizeof(int));
            *(int *)value = private_num->valueint;              
            break;
        }
        case JWT_CLAIM_TYPE_PRIVATE_BOOL: {
            cJSON *private_bool = cJSON_GetObjectItem(payload_root, name);
            if (NULL == private_bool || !cJSON_IsBool(private_bool))
                goto exit_2;

            value = malloc(sizeof(bool));
            *(int *)value = private_bool->valueint;                 
            break;
        }
        case JWT_CLAIM_TYPE_PRIVATE_JSON: {
            cJSON *private_json = cJSON_GetObjectItem(payload_root, name);
            if (NULL == private_json || !cJSON_IsObject(private_json))
                goto exit_2;            

            value = (void *)cJSON_Duplicate(private_json, cJSON_True);
            break;
        }         
        default:
            goto exit_2;            
    }

exit_2:
    if (payload_root)
        cJSON_Delete(payload_root);

exit_1:
    if (payload)
        free(payload);

    return value;
}

char *iotex_jwt_claim_serialize(JWTClaim_handle handle, bool format)
{
    char *jwt_claim_serialize = NULL;

    if (NULL == handle)
        return NULL;

    if (NULL == handle->claim)
        return NULL;

    if (format)
        jwt_claim_serialize = cJSON_Print(handle->claim);
    else
        jwt_claim_serialize = cJSON_PrintUnformatted(handle->claim);

    return jwt_claim_serialize;
}

char *iotex_jwt_serialize(JWTClaim_handle handle, enum JWTType type, enum JWAlogrithm alg, JWK *jwk)
{
    if (NULL == handle || NULL == jwk)
        return NULL;

    char *jwt_claim_serialize = iotex_jwt_claim_serialize(handle, true);
    if (NULL == jwt_claim_serialize)
        return NULL;

    char *jwt_serialize = NULL;

    switch (type) {
        case JWT_TYPE_JWS:
            jwt_serialize = iotex_jws_compact_serialize(alg, jwt_claim_serialize, strlen(jwt_claim_serialize), jwk);
            break;
        case JWT_TYPE_JWE:
            break;
        default:
            break;
    }

    free(jwt_claim_serialize);

    return jwt_serialize;
}

bool iotex_jwt_verify(char *jwt_serialize, enum JWTType type, enum JWAlogrithm alg, JWK *jwk)
{
    if (NULL == jwk || NULL == jwt_serialize)
        return false;

    switch (type) {
        case JWT_TYPE_JWS:
            return iotex_jws_compact_verify(alg, jwt_serialize, jwk);
        case JWT_TYPE_JWE:
        default:
            return false;
    }

    return false;
}

