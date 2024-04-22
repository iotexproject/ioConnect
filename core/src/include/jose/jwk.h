#ifndef __IOTEX_JOSE_JWK_H__
#define __IOTEX_JOSE_JWK_H__

#include "include/server/crypto.h" 
#include "include/jose/common.h"

typedef char Base64url;

enum JWKRegistryType {
    JWKREGISTRYTYPE_OWNER,
    JWKREGISTRYTYPE_PEER,
};

enum JWAlogrithm {
    None,
    HS256,      // HMAC using SHA-256
    HS384,
    HS512,
    RS256,      // RSASSA-PKCS1-v1_5 using SHA-256
    RS384,
    RS512,
    PS256,      // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS384,
    PS512,
    EdDSA,
    ES256,      // ECDSA using P-256 and SHA-256
    ES384,
    ES256K,
    ES256KR,
};

enum JWKType {
    JWKTYPE_EC = 1,
    JWKTYPE_RSA,
    JWKTYPE_Symmetric,          // rename oct
    JWKTYPE_OKP,    
};

enum KnownKeyAlg {
    Ed25519,
    X25519,
    P256,
    K256,
    Unsupported,
};

enum JWKSupportKeyAlg {
    JWK_SUPPORT_KEY_ALG_ED25519,
    JWK_SUPPORT_KEY_ALG_P256,
    JWK_SUPPORT_KEY_ALG_K256,
};


typedef struct _ECParams {
    char crv[12];                      // rename "crv"
    Base64url x_coordinate[48];        // rename "x"
    Base64url y_coordinate[48];        // rename "y"
    Base64url ecc_private_key[48];     // rename "d" : option
}ECParams;

typedef struct {
    char *RSAParams_todo;               // TODO:
}RSAParams;

typedef struct {
    char *SymmetricParams_todo;         // TODO:
}SymmetricParams;

typedef struct {
    char crv[12];                       // rename "crv"
    Base64url *public_key;              // rename "x"
    Base64url *private_key;             // rename "d" : option   
}OctetParams;

enum JWKPublickeyUseParams {
    JWKPubKeyUseNone,
    JWKPubKeyUseSIG,
    JWKPubKeyUseENC,
};

enum JWKKeyOpsParams {
    JWKKeyOpsNone,
    JWKKeyOpsSign,
    JWKKeyOpsVerigy,
    JWKKeyOpsEncrypt,
    JWKKeyOpsDecrypt,
    JWKKeyOpsWrapKey,
    JWKKeyOpsUnWrapKey,
    JWKKeyOpsDeriveKey,
    JWKKeyOpsDeriveBits,
};

typedef struct {
    enum JWKPublickeyUseParams public_key_use;
    enum JWKKeyOpsParams key_operations;
    unsigned int key_id;
    char *x509_url;
    char *x509_certificate_chain;
    Base64url x509_thumbprint_sha1[28];
    Base64url x509_thumbprint_sha256[44] ;
    enum JWAlogrithm alg;
    enum JWKType type;
    union {
        ECParams ec;
        RSAParams rsa;
        SymmetricParams oct;
        OctetParams okp;
    } Params;    
} JWK;

#define IOTEX_JWK_LIFETIME_VOLATILE             0x00
#define IOTEX_JWK_LIFETIME_PERSISTENT           0x01

enum JWAlogrithm iotex_jwk_get_algorithm(JWK *jwk);
enum KnownKeyAlg iotex_jwk_get_key_alg(JWK *jwk);

JWK *iotex_jwk_copy(JWK *jwk, bool skipPrivate);
JWK *iotex_jwk_to_public(JWK *jwk);
JWK *iotex_jwk_generate(enum JWKType type, enum JWKSupportKeyAlg keyalg,
                                int lifetime, unsigned int key_usage, unsigned int alg, unsigned int *key_id);
JWK* iotex_jwk_generate_by_secret(uint8_t *secret, unsigned int secret_size,
                                enum JWKType type, enum JWKSupportKeyAlg keyalg,
                                int lifetime, unsigned int key_usage, unsigned int alg, unsigned int *key_id);                                
JWK *iotex_jwk_get_jwk_from_json_value(void *json_value);                                

void *_did_jwk_json_generate(JWK *jwk);
void iotex_jwk_destroy(JWK *jwk);

char *iotex_jwk_serialize(JWK *jwk, bool format);
char *iotex_jwk_generate_kid(char *method, JWK *jwk);

bool iotex_jwk_equals(JWK *jwk1, JWK *jwk2, bool skipPri);

jose_status_t iotex_jwk_get_pubkey_from_jwk(JWK *jwk, char *outdata, size_t *outdata_len);
jose_status_t iotex_pubkey_uncompress_convert_compress(const char *uncompress, char *compress);

psa_key_id_t iotex_jwk_get_psa_key_id_from_didurl(char *didurl);

#endif

