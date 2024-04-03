#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/jose/jws.h"
#include "include/jose/jwk.h"
#include "include/jose/jwt.h"

#include "include/utils/cJSON/cJSON.h"

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
            cJSON_AddItemToObject(handle->claim, name, (cJSON *)value);            
        
        default:
            return JOSE_ERROR_INVALID_ARGUMENT;            
    }

    return JOSE_SUCCESS;
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

    printf("jwt_claim_serialize : %s\n", jwt_claim_serialize);        

    char *jwt_serialize = iotex_jws_compact_serialize(alg, jwt_claim_serialize, strlen(jwt_claim_serialize), jwk);

    free(jwt_claim_serialize);

    return jwt_serialize;
}

