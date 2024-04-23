#ifndef __IOTEX_JOSE_JWT_H__
#define __IOTEX_JOSE_JWT_H__

#include "include/jose/common.h"
#include "include/utils/cJSON/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _JWTClaim {

    char *iss;          // Issuer   : Identifies the principal that issued the JWT.[OPTIONAL]
    char *sub;          // Subject  : Identifies the principal that is the subject of the JWT.[OPTIONAL]
    char *aud;          // Audience : Identifies the recipients that the JWT is intended for.[OPTIONAL]

    time_t exp;         // Expiration Time [OPTIONAL]
    time_t nbf;         // Not Before [OPTIONAL]
    time_t iat;         // Issurd At [OPTIONAL]

    char *jti;          // JWT ID ：provides a unique identifier for the JWT.[OPTIONAL]

} JWTClaim;

typedef struct _JWTClaim_handle {
    
    cJSON *claim;

} *JWTClaim_handle;

enum JWTClaimType {
    JWT_CLAIM_TYPE_ISS,
    JWT_CLAIM_TYPE_SUB,
    JWT_CLAIM_TYPE_AUD,
    JWT_CLAIM_TYPE_EXP,
    JWT_CLAIM_TYPE_NBF,
    JWT_CLAIM_TYPE_IAT,
    JWT_CLAIM_TYPE_JTI,
    JWT_CLAIM_TYPE_PRIVATE_STRING,
    JWT_CLAIM_TYPE_PRIVATE_NUM,
    JWT_CLAIM_TYPE_PRIVATE_BOOL,
    JWT_CLAIM_TYPE_PRIVATE_JSON,
};

enum JWTType {
  JWT_TYPE_JWS,
  JWT_TYPE_JWE,
};

JWTClaim_handle iotex_jwt_claim_new(void);
void iotex_jwt_claim_destroy(JWTClaim_handle handle);

jose_status_t iotex_jwt_claim_set_value(JWTClaim_handle handle, enum JWTClaimType type, char *name, void *value);
void * iotex_jwt_claim_get_value(char *jwt_serialize, enum JWTType jwt_type, enum JWTClaimType type, char *name);
char *iotex_jwt_claim_serialize(JWTClaim_handle handle, bool format);
char *iotex_jwt_serialize(JWTClaim_handle handle, enum JWTType type, enum JWAlogrithm alg, JWK *jwk);
bool iotex_jwt_verify(char *jwt_serialize, enum JWTType type, enum JWAlogrithm alg, JWK *jwk);

#ifdef __cplusplus
}
#endif


#endif
