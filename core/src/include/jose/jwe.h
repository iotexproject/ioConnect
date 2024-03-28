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

#define DIDCOMM_JWE_ENCRPTY_TYP     "application/didcomm-encrypted+json"

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
    /// Must be `application/didcomm-encrypted+json` or `didcomm-encrypted+json` for now.
    /// Something like `application/didcomm-encrypted+cbor` can be introduced in the
    /// future.
    char *typ;

    /// Cryptographic algorithm used to encrypt or determine the value of the CEK.
    enum KWAlgorithms alg;

    /// Identifies the content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag.
    enum EncAlgorithm enc;

    /// Sender KID as DID Url.
    /// If absent implementations MUST be able to resolve the sender kid from the `apu` header.
    char *skid;     // skip_serializing_if = "Option::is_none"

    /// BASE64URL("skid" header value),
    char *apu;      // skip_serializing_if = "Option::is_none"

    /// BASE64URL(SHA256(CONCAT('.', SORT([recipients[0].kid, ..., recipients[n].kid])))))
    char *apv;

    /// EPK generated once for all recipients.
    /// It MUST be of the same type and curve as all recipient keys since kdf
    /// with the sender key must be on the same curve.
    void *epk;

} JweProtectedHeader;

typedef struct _JWE {
    /// BASE64URL(UTF8(JWE Protected Header))
    /// Note: this field value is used as AAD for JWE Ciphertext
    char *_protected;

    /// Array of recipient-specific objects
    Recipient *recipients[4];

    /// BASE64URL(JWE Initialization Vector)
    char *iv;

    /// BASE64URL(JWE Ciphertext)
    char *ciphertext;

    /// BASE64URL(JWE Authentication Tag)
    char *tag;

} JWE;

char *iotex_jwe_encrypt_plaintext(psa_key_id_t key_id, char *plaintext, size_t pLen, char *nonce, size_t nonce_len, char *ad, size_t ad_len, size_t *ciphertext_length);
char *iotex_jwe_encrypt_protected(enum KWAlgorithms KwAlg, enum EncAlgorithm enAlg, char *sender, char *recipients_kid[4], JWK *epk);
char *iotex_jwe_encrypt(char *plaintext, enum KWAlgorithms alg, enum EncAlgorithm enc, char *sender, JWK *sJWK, char * recipients[4]);

// typedef const JWK *(*key_locator)(jwe_t *jwe, jwe_header_t *hdr, void *);

/**
 * Creates a new JWE by encrypting the given plaintext within the given header
 * and JWK.
 *
 * If the header provided indicates an algorithm requiring an asymmetric key
 * (e.g. RSA-OAEP), the provided JWK must be asymmetric (e.g. RSA or EC).
 *
 * If the header provided indicates an algorithm requiring a symmetric key
 * (e.g. (dir), the provided JWK must be symmetric (e.g. oct).
 *
 * \param jwk [in] the key to use for encrypting the JWE.
 * \param protected_header [in] additional header values to include in the JWE protected header.
 * \param plaintext [in] the plaintext to be encrypted in the JWE payload.
 * \param plaintext_len [in] the length of the plaintext.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns a newly generated JWE with the given plaintext as the payload.
 */
// jwe_t *
// cjose_jwe_encrypt(const JWK *jwk, jwe_header_t *header, const uint8_t *plaintext, size_t plaintext_len);

/**
 * Creates a new JWE by encrypting the given plaintext with multiple keys.
 * \see ::cjose_jwe_encrypt for key requirements.
 * \param recipients [in] array of recipient objects. Each element must have the
 *        key of the recipient, and may have optional (not NULL) unprotected header.
 *        Unprotected header is retained by this function, and can be safely released by the
 *        caller if no longer needed. The key is only used within the scope of this function.
 * \param recipient_count effective length of the recipients array, specifying how many
 *        recipients there is.
 * \param protected_header [in] additional header values to include in the JWE protected header. The header
 *        is retained by JWE and should be released by the caller if no longer needed.
 * \param unprotected_header [in] additional header values to include in the shared JWE unprotected header,
 *        can be NULL. The header is retained by JWE and should be released by the caller if no longer needed.
 * \param plaintext [in] the plaintext to be encrypted in the JWE payload.
 * \param plaintext_len [in] the length of the plaintext.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns a newly generated JWE with the given plaintext as the payload.
 */
// jwe_t *cjose_jwe_encrypt_multi(const jwe_recipient_t * recipients,
//                                     size_t recipient_count,
//                                     jwe_header_t *protected_header,
//                                     jwe_header_t *shared_unprotected_header,
//                                     const uint8_t *plaintext,
//                                     size_t plaintext_len);

/**
 * Creates a compact serialization of the given JWE object.
 *
 * \param jwe [in] The JWE object to be serialized.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns A pointer to a compact serialization of this JWE.  Note
 *        the returned string pointer is owned by the caller, the caller
 *        must free it directly when no longer needed, or the memory will be
 *        leaked.
 */
// char *cjose_jwe_export(jwe_t *jwe);

/**
 * Creates a JSON serialization of the given JWE object.
 *
 * \param jwe [in] The JWE object to be serialized.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns A pointer to a JSON serialization of this JWE.  Note
 *        the returned string pointer is owned by the caller, the caller
 *        must free it directly when no longer needed, or the memory will be
 *        leaked.
 */
// char *cjose_jwe_export_json(jwe_t *jwe);

/**
 * Creates a new JWE object from the given JWE compact serialization.
 *
 * Note the current implementation only recognizes the JWE compact serialization
 * format.
 *
 * \param compact [in] a JWE in serialized form.
 * \param compact_len [in] the length of the compact serialization.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns a newly generated JWE object from the given JWE serialization.
 */
// jwe_t *cjose_jwe_import(const char *compact, size_t compact_len);

/**
 * Creates a new JWE object from the given JWE compact serialization.
 *
 * Note the current implementation only recognizes the JWE compact serialization
 * format.
 *
 * \param json [in] a JWE in a JSON serialized form.
 * \param json_len [in] the length of the serialization.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns a newly generated JWE object from the given JWE JSON serialization.
 */
// jwe_t *cjose_jwe_import_json(const char *json, size_t json_len);

/**
 * Decrypts the JWE object using the given JWK.  Returns the plaintext data of
 * the JWE payload.
 *
 * \param jwe [in] the JWE object to decrypt.
 * \param jwk [in] the key to use for decrypting.
 * \param content_len [out] The number of bytes in the returned buffer.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns The decrypted content.  Note the caller is responsible for free'ing
 *        this buffer when no longer in use.  Failure to do so will result in
 *        a memory leak.
 */
// uint8_t *cjose_jwe_decrypt(jwe_t *jwe, const JWK *jwk, size_t *content_len);

/**
 * Decrypts the JWE object using one or more provided JWKs. Returns the plaintext data
 * of the JWE payload. The key to be used for decryption must be provided by the specified call back.
 * The call back will be invoked for each recipient information in the JWE.
 * If no key is available for a particular recipient information, `NULL` must be returned.
 * More than one key can be returned, decryption is considered successful if the content
 * decrypts and validates against all returned non-NULL keys, and at least one key was attempted.
 *
 * \param jwe [in] the JWE object to decrypt.
 * \param jwk [in] key_locator callback for finding keys
 * \param data [in] custom data argument that is passed to the key locator callback.
 * \param content_len [out] The number of bytes in the returned buffer.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns The decrypted content. Note the caller is responsible for free'ing
 *        this buffer when no longer in use.  Failure to do so will result in
 *        a memory leak.
 */
// uint8_t *cjose_jwe_decrypt_multi(jwe_t *jwe, key_locator key_locator, void *data, size_t *content_len);

/**
 * Returns the protected header of the JWE object.
 *
 * **NOTE:** The returned header is still owned by the JWE object. Users must
 * call `cjose_header_retain()` if it is expected to be valid after the
 * owning `cjose_jwe_t` is released.
 *
 * \param jwe [in] the JWE object for which the protected header is requested.
 * \returns the (parsed) protected header
 */
// jwe_header_t *cjose_jwe_get_protected(jwe_t *jwe);

/**
 * Releases the given JWE object.
 *
 * \param jwe the JWE to be released.  If null, this is a no-op.
 */
// void cjose_jwe_release(jwe_t *jwe);

#ifdef __cplusplus
}
#endif

#endif // CJOSE_JWE_H
