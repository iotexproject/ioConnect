#ifndef __IOTEX_JOSE_JWS_H__
#define __IOTEX_JOSE_JWS_H__

#include "include/jose/common.h"
#include "include/jose/jwk.h"

#include "include/utils/cJSON/cJSON.h"

typedef unsigned int jws_handle_t;

typedef struct _JWSCompactHeader {
    char *typ;                  // Media type of this complete JWS.
    enum JWAlogrithm alg;       // Cryptographic algorithm used to produce signature.
    char *kid;                  // KID used to produce signature as DID URL.
} JWSCompactHeader;

typedef struct _JWSHeader {
    char *kid;                  // KID used to produce signature as DID URL.
} JWSHeader;

typedef struct _JWSProtectedHeader {
    char typ[32];               // Must be `application/didcomm-signed+json` or `didcomm-signed+json` for now.
    enum JWAlogrithm alg;       // Cryptographic algorithm used to produce signature.
} JWSProtectedHeader;

typedef struct _JWSSignature {
    JWSHeader *header;          // JWS unprotected header. Note it isn't serialized and not integrity protected
    char *_protected;            // BASE64URL(UTF8(JWS Protected Header))
    char *signature;            // BASE64URL(JWS signature). Note JWS signature input is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
} JWSSignature;

typedef struct _JWS {
    JWSSignature *signatures[4];    // Array of signatures
    char *payload;                  // BASE64URL(JWS Payload)
} JWS;

char *iotex_jws_compact_serialize(enum JWAlogrithm alg, char *plaintext, size_t plaintext_size, JWK *jwk);
jws_handle_t iotex_jws_general_json_serialize_init(char *plaintext, size_t plaintext_size);
jose_status_t iotex_jws_general_json_serialize_update(jws_handle_t handle, enum JWAlogrithm alg, char *kid, JWK *jwk);
char *iotex_jws_general_json_serialize_finish(jws_handle_t handle, bool format);
char *iotex_jws_flattened_json_serialize(enum JWAlogrithm alg, char *plaintext, size_t plaintext_size, char *kid, enum JWS_USAGE usage, JWK *jwk, bool format);
bool iotex_jws_compact_verify(enum JWAlogrithm alg, char *jws_msg, JWK *jwk);

jose_status_t _find_point_position(char *jws, uint32_t *first, uint32_t *second);

#endif