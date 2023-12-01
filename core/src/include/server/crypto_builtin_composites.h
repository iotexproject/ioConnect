#ifndef PSA_CRYPTO_BUILTIN_COMPOSITES_H
#define PSA_CRYPTO_BUILTIN_COMPOSITES_H

#include "include/server/crypto_driver_common.h"

/*
 * MAC multi-part operation definitions.
 */
#if defined(IOTEX_PSA_BUILTIN_ALG_CMAC) || \
    defined(IOTEX_PSA_BUILTIN_ALG_HMAC)
#define IOTEX_PSA_BUILTIN_MAC
#endif

#if defined(IOTEX_PSA_BUILTIN_ALG_HMAC) || defined(PSA_CRYPTO_DRIVER_TEST)
typedef struct
{
    /** The HMAC algorithm in use */
    psa_algorithm_t alg;
    /** The hash context. */
    struct psa_hash_operation_s hash_ctx;
    /** The HMAC part of the context. */
    uint8_t opad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
} iotex_psa_hmac_operation_t;

#define IOTEX_PSA_HMAC_OPERATION_INIT {0, PSA_HASH_OPERATION_INIT, {0}}
#endif /* IOTEX_PSA_BUILTIN_ALG_HMAC */

#include "include/iotex/cmac.h"

typedef struct
{
    psa_algorithm_t alg;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(IOTEX_PSA_BUILTIN_ALG_HMAC) || defined(PSA_CRYPTO_DRIVER_TEST)
        iotex_psa_hmac_operation_t hmac;
#endif /* IOTEX_PSA_BUILTIN_ALG_HMAC */
#if defined(IOTEX_PSA_BUILTIN_ALG_CMAC) || defined(PSA_CRYPTO_DRIVER_TEST)
        iotex_cipher_context_t cmac;
#endif /* IOTEX_PSA_BUILTIN_ALG_CMAC */
    } ctx;
} iotex_psa_mac_operation_t;

#define IOTEX_PSA_MAC_OPERATION_INIT {0, {0}}

#if defined(IOTEX_PSA_BUILTIN_ALG_GCM) || \
    defined(IOTEX_PSA_BUILTIN_ALG_CCM) || \
    defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
#define IOTEX_PSA_BUILTIN_AEAD  1
#endif

/* Context structure for the IOTEX AEAD implementation. */
typedef struct
{
    psa_algorithm_t alg;
    psa_key_type_t  key_type;

    unsigned int is_encrypt : 1;

    uint8_t tag_length;

    union
    {
        unsigned dummy; /* Enable easier initializing of the union. */
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
        iotex_ccm_context ccm;
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
        iotex_gcm_context gcm;
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        iotex_chachapoly_context chachapoly;
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */

    } ctx;

} iotex_psa_aead_operation_t;

#define IOTEX_PSA_AEAD_OPERATION_INIT {0, 0, 0, 0, {0}}

#endif /* PSA_CRYPTO_BUILTIN_COMPOSITES_H */
