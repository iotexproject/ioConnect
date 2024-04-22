#ifndef __IOTEX_REGISTRY_H__
#define __IOTEX_REGISTRY_H__

#include "include/dids/common.h"
#include "include/jose/jwk.h"

#define IOTEX_REGISTRY_MAX     4

did_status_t iotex_registry_item_register(char *kid, JWK *jwk);
did_status_t iotex_registry_item_unregister(char *kid);

JWK *iotex_registry_find_jwk_by_kid(char *kid);

#endif