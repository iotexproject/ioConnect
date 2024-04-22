#include <stdlib.h>
#include <string.h>

#include "include/server/crypto.h"
#include "include/dids/did/did.h"
#include "include/dids/did/registry.h"
#include "include/utils/cJSON/cJSON.h"

typedef struct _registry_item {
    char *kid;
    JWK  *jwk;
} registry_item;

static registry_item items[IOTEX_REGISTRY_MAX] = {0};

did_status_t iotex_registry_item_register(char *kid, JWK *jwk)
{
    int idx = 0;

    if (NULL == kid || NULL == jwk)
        return DID_ERROR_INVALID_ARGUMENT;

    for (idx = 0; idx < IOTEX_REGISTRY_MAX; idx++) {
        if (NULL == items[idx].kid) {

            items[idx].kid = malloc(strlen(kid) + 1);
            if (NULL == items[idx].kid)
                return DID_ERROR_INSUFFICIENT_MEMORY;
            memset(items[idx].kid, 0, strlen(kid) + 1);
            strcpy(items[idx].kid, kid);

            if (items[idx].jwk)
                iotex_jwk_destroy(items[idx].jwk);

            items[idx].jwk = iotex_jwk_copy(jwk, false);
            if (NULL == items[idx].jwk) {
                free(items[idx].kid);
                return DID_ERROR_NOT_SUPPORTED;
            }

            return (did_status_t)idx;
        }
    }

    return DID_ERROR_BUFFER_FULL;
}

did_status_t iotex_registry_item_unregister(char *kid)
{
    if (NULL == kid)
        return DID_ERROR_INVALID_ARGUMENT;

    for (int i = 0; i < IOTEX_REGISTRY_MAX; i++) {

        if (NULL == items[i].kid)
            continue;

        if (!strcmp(items[i].kid, kid)) {
            free(items[i].kid);
            items[i].kid = NULL;

            if (items[i].jwk) {
                iotex_jwk_destroy(items[i].jwk);
                items[i].jwk = NULL;
            }

            return DID_SUCCESS;
        }
    }    

    return DID_ERROR_DOES_NOT_EXIST;
}

JWK *iotex_registry_find_jwk_by_kid(char *kid)
{
    if (NULL == kid)
        return NULL;

    for (int i = 0; i < IOTEX_REGISTRY_MAX; i++) {
        if (NULL == items[i].kid)
            continue;

        if (!strcmp(items[i].kid, kid))
            return items[i].jwk;
    }    

    return NULL;           
}
