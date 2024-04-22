/**
 * \file  jwe.h
 * \brief Functions and data structures for interacting with
 *        JSON Web Encryption (JWE) objects.
 *
 */

#ifndef __IOTEX_JOSE_JWE_H__
#define __IOTEX_JOSE_JWE_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "include/jose/common.h"
#include "include/jose/jwk.h"
#include "include/utils/cJSON/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

enum EncAlgorithm {
    A256cbcHs512,       // rename = "A256CBC-HS512"
    Xc20P,              // rename = "XC20P"
    A256Gcm,            // rename = "A256GCM"
};

enum KWAlgorithms {
    Ecdh1puA256kw,      // rename = "ECDH-1PU+A256KW"
    EcdhEsA256kw,       // rename = "ECDH-ES+A256KW"
};

typedef struct _PerRecipientHeader {
    char *kid;          // Recipient KID as DID URL
} PerRecipientHeader;

typedef struct _Recipient {
    PerRecipientHeader header;      // Per-recipient header, Note it isn't serialized and not integrity protected. 
    char *encrypted_key;            // BASE64URL(JWE Encrypted Key)
} Recipient;

typedef struct _JweProtectedHeader {
    char *typ;              // Must be `application/didcomm-encrypted+json` or `didcomm-encrypted+json` for now.
    enum KWAlgorithms alg;  // Cryptographic algorithm used to encrypt or determine the value of the CEK.
    enum EncAlgorithm enc;  // Identifies the content encryption algorithm used to perform authenticated encryption on the plaintext to produce the ciphertext and the Authentication Tag.
    char *skid;             // Sender KID as DID Url. skip_serializing_if = "Option::is_none" but if absent implementations MUST be able to resolve the sender kid from the `apu` header.
    char *apu;              // BASE64URL("skid" header value), skip_serializing_if = "Option::is_none"
    char *apv;              // BASE64URL(SHA256(CONCAT('.', SORT([recipients[0].kid, ..., recipients[n].kid])))))
    void *epk;              // EPK generated once for all recipients. It MUST be of the same type and curve as all recipient keys since kdf with the sender key must be on the same curve.
} JweProtectedHeader;

typedef struct _JWE { 
    char *_protected;           // BASE64URL(UTF8(JWE Protected Header)) Note: this field value is used as AAD for JWE Ciphertext
    char *iv;                   // BASE64URL(JWE Initialization Vector)
    char *ciphertext;           // BASE64URL(JWE Ciphertext)
    char *tag;                  // BASE64URL(JWE Authentication Tag)
    Recipient *recipients[JOSE_JWE_RECIPIENTS_MAX];   // Array of recipient-specific objects
} JWE;

char *iotex_jwe_encrypt_plaintext(psa_key_id_t key_id, char *plaintext, size_t pLen, char *nonce, size_t nonce_len, char *ad, size_t ad_len, size_t *ciphertext_length);
char *iotex_jwe_encrypt_protected(enum KWAlgorithms KwAlg, enum EncAlgorithm enAlg, char *sender, char *recipients_kid[4], JWK *epk);
char *iotex_jwe_encrypt(char *plaintext, enum KWAlgorithms alg, enum EncAlgorithm enc, char *sender, JWK *sJWK, char *recipients_kid[JOSE_JWE_RECIPIENTS_MAX], bool format);
char *iotex_jwe_decrypt(char *jwe_serialize, enum KWAlgorithms alg, enum EncAlgorithm enc, char *sender, JWK *sJWK, char *recipients_kid);

#ifdef __cplusplus
}
#endif

#endif
