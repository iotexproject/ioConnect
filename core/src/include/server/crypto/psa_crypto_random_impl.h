#ifndef PSA_CRYPTO_RANDOM_IMPL_H
#define PSA_CRYPTO_RANDOM_IMPL_H

#include "include/iotex/psa_util.h"

#if defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG)

#include <string.h>
#include "include/iotex/entropy.h" // only for error codes
#include "include/server/crypto.h"

typedef iotex_psa_external_random_context_t iotex_psa_random_context_t;

/* Trivial wrapper around psa_generate_random(). */
int iotex_psa_get_random( void *p_rng,
                            unsigned char *output,
                            size_t output_size );

/* The PSA RNG API doesn't need any externally maintained state. */
#define IOTEX_PSA_RANDOM_STATE NULL

#else /* IOTEX_PSA_CRYPTO_EXTERNAL_RNG */

/* Choose a DRBG based on configuration and availability */
#if defined(IOTEX_PSA_HMAC_DRBG_MD_TYPE)

#include "include/iotex/hmac_drbg.h"

#elif defined(IOTEX_CTR_DRBG_C)

#include "include/iotex/ctr_drbg.h"

#elif defined(IOTEX_HMAC_DRBG_C)

#include "include/iotex/hmac_drbg.h"
#if defined(IOTEX_SHA512_C) && defined(IOTEX_SHA256_C)
#include <limits.h>
#if SIZE_MAX > 0xffffffff
/* Looks like a 64-bit system, so prefer SHA-512. */
#define IOTEX_PSA_HMAC_DRBG_MD_TYPE IOTEX_MD_SHA512
#else
/* Looks like a 32-bit system, so prefer SHA-256. */
#define IOTEX_PSA_HMAC_DRBG_MD_TYPE IOTEX_MD_SHA256
#endif
#elif defined(IOTEX_SHA512_C)
#define IOTEX_PSA_HMAC_DRBG_MD_TYPE IOTEX_MD_SHA512
#elif defined(IOTEX_SHA256_C)
#define IOTEX_PSA_HMAC_DRBG_MD_TYPE IOTEX_MD_SHA256
#else
#error "No hash algorithm available for HMAC_DBRG."
#endif

#else
#error "No DRBG module available for the psa_crypto module."
#endif

#include "include/iotex/entropy.h"

/** Initialize the PSA DRBG.
 *
 * \param p_rng        Pointer to the Mbed TLS DRBG state.
 */
static inline void iotex_psa_drbg_init( iotex_psa_drbg_context_t *p_rng )
{
#if defined(IOTEX_CTR_DRBG_C)
    iotex_ctr_drbg_init( p_rng );
#elif defined(IOTEX_HMAC_DRBG_C)
    iotex_hmac_drbg_init( p_rng );
#endif
}

/** Deinitialize the PSA DRBG.
 *
 * \param p_rng        Pointer to the Mbed TLS DRBG state.
 */
static inline void iotex_psa_drbg_free( iotex_psa_drbg_context_t *p_rng )
{
#if defined(IOTEX_CTR_DRBG_C)
    iotex_ctr_drbg_free( p_rng );
#elif defined(IOTEX_HMAC_DRBG_C)
    iotex_hmac_drbg_free( p_rng );
#endif
}

/** The type of the PSA random generator context.
 *
 * The random generator context is composed of an entropy context and
 * a DRBG context.
 */
typedef struct
{
    void (* entropy_init )( iotex_entropy_context *ctx );
    void (* entropy_free )( iotex_entropy_context *ctx );
    iotex_entropy_context entropy;
    iotex_psa_drbg_context_t drbg;
} iotex_psa_random_context_t;

#if !defined(_MSC_VER)
static iotex_f_rng_t *const iotex_psa_get_random;
#endif

/** The maximum number of bytes that iotex_psa_get_random() is expected to
 * return.
 */
#if defined(IOTEX_CTR_DRBG_C)
#define IOTEX_PSA_RANDOM_MAX_REQUEST IOTEX_CTR_DRBG_MAX_REQUEST
#elif defined(IOTEX_HMAC_DRBG_C)
#define IOTEX_PSA_RANDOM_MAX_REQUEST IOTEX_HMAC_DRBG_MAX_REQUEST
#endif

/** A pointer to the PSA DRBG state.
 *
 * This variable is only intended to be used through the macro
 * #IOTEX_PSA_RANDOM_STATE.
 */
/* psa_crypto.c sets this variable to a pointer to the DRBG state in the
 * global PSA crypto state. */
/* The type `iotex_psa_drbg_context_t` is defined in
 * include/mbedtls/psa_util.h so that `iotex_psa_random_state` can be
 * declared there and be visible to application code. */
extern iotex_psa_drbg_context_t *const iotex_psa_random_state;

/** A pointer to the PSA DRBG state.
 *
 * This macro expands to an expression that is suitable as the \c p_rng
 * parameter to pass to iotex_psa_get_random().
 *
 * This macro exists in all configurations where the psa_crypto module is
 * enabled. Its expansion depends on the configuration.
 */
#define IOTEX_PSA_RANDOM_STATE iotex_psa_random_state

/** Seed the PSA DRBG.
 *
 * \param entropy       An entropy context to read the seed from.
 * \param custom        The personalization string.
 *                      This can be \c NULL, in which case the personalization
 *                      string is empty regardless of the value of \p len.
 * \param len           The length of the personalization string.
 *
 * \return              \c 0 on success.
 * \return              An Mbed TLS error code (\c IOTEX_ERR_xxx) on failure.
 */
static inline int iotex_psa_drbg_seed(
    iotex_entropy_context *entropy,
    const unsigned char *custom, size_t len )
{
#if defined(IOTEX_CTR_DRBG_C)
    return( iotex_ctr_drbg_seed( IOTEX_PSA_RANDOM_STATE,
                                   iotex_entropy_func,
                                   entropy,
                                   custom, len ) );
#elif defined(IOTEX_HMAC_DRBG_C)
    return( iotex_hmac_drbg_seed( IOTEX_PSA_RANDOM_STATE, 0, 0, 0, custom, len ) );
#endif
}

#endif /* IOTEX_PSA_CRYPTO_EXTERNAL_RNG */

#endif /* PSA_CRYPTO_RANDOM_IMPL_H */
