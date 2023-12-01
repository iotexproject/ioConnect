#ifndef PSA_CRYPTO_BUILTIN_PRIMITIVES_H
#define PSA_CRYPTO_BUILTIN_PRIMITIVES_H

#include "include/server/crypto_driver_common.h"

/*
 * Hash multi-part operation definitions.
 */

#include "include/iotex/md5.h"
#include "include/iotex/ripemd160.h"
#include "include/iotex/sha1.h"
#include "include/iotex/sha256.h"
#include "include/iotex/sha512.h"

#if defined(IOTEX_PSA_BUILTIN_ALG_MD5) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160) || \
    defined(IOTEX_PSA_BUILTIN_ALG_SHA_1) || \
    defined(IOTEX_PSA_BUILTIN_ALG_SHA_224) || \
    defined(IOTEX_PSA_BUILTIN_ALG_SHA_256) || \
    defined(IOTEX_PSA_BUILTIN_ALG_SHA_384) || \
    defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
#define IOTEX_PSA_BUILTIN_HASH
#endif

typedef struct
{
    psa_algorithm_t alg;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
        iotex_md5_context md5;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
        iotex_ripemd160_context ripemd160;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
        iotex_sha1_context sha1;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256) || \
    defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
        iotex_sha256_context sha256;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512) || \
    defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
        iotex_sha512_context sha512;
#endif
    } ctx;
} iotex_psa_hash_operation_t;

#define IOTEX_PSA_HASH_OPERATION_INIT {0, {0}}

/*
 * Cipher multi-part operation definitions.
 */

#include "include/iotex/cipher.h"

#if defined(IOTEX_PSA_BUILTIN_ALG_STREAM_CIPHER) || \
    defined(IOTEX_PSA_BUILTIN_ALG_CTR) || \
    defined(IOTEX_PSA_BUILTIN_ALG_CFB) || \
    defined(IOTEX_PSA_BUILTIN_ALG_OFB) || \
    defined(IOTEX_PSA_BUILTIN_ALG_ECB_NO_PADDING) || \
    defined(IOTEX_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(IOTEX_PSA_BUILTIN_ALG_CBC_PKCS7)
#define IOTEX_PSA_BUILTIN_CIPHER  1
#endif

typedef struct {
    psa_algorithm_t alg;
    uint8_t iv_length;
    uint8_t block_length;
    union {
        unsigned int dummy;
        iotex_cipher_context_t cipher;
    } ctx;
} iotex_psa_cipher_operation_t;

#define IOTEX_PSA_CIPHER_OPERATION_INIT {0, 0, 0, {0}}

#endif /* PSA_CRYPTO_BUILTIN_PRIMITIVES_H */
