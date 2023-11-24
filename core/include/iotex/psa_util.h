#ifndef IOTEX_PSA_UTIL_H
#define IOTEX_PSA_UTIL_H

#include "include/iotex/build_info.h"

#if defined(IOTEX_PSA_CRYPTO_C)

#include "include/server/crypto.h"

#include "include/iotex/ecp.h"
#include "include/iotex/md.h"
#include "include/iotex/pk.h"
#include "include/iotex/oid.h"
#include "include/iotex/error.h"

#include <string.h>

/* Translations for symmetric crypto. */

static inline psa_key_type_t iotex_psa_translate_cipher_type(
    iotex_cipher_type_t cipher )
{
    switch( cipher )
    {
        case IOTEX_CIPHER_AES_128_CCM:
        case IOTEX_CIPHER_AES_192_CCM:
        case IOTEX_CIPHER_AES_256_CCM:
        case IOTEX_CIPHER_AES_128_CCM_STAR_NO_TAG:
        case IOTEX_CIPHER_AES_192_CCM_STAR_NO_TAG:
        case IOTEX_CIPHER_AES_256_CCM_STAR_NO_TAG:
        case IOTEX_CIPHER_AES_128_GCM:
        case IOTEX_CIPHER_AES_192_GCM:
        case IOTEX_CIPHER_AES_256_GCM:
        case IOTEX_CIPHER_AES_128_CBC:
        case IOTEX_CIPHER_AES_192_CBC:
        case IOTEX_CIPHER_AES_256_CBC:
        case IOTEX_CIPHER_AES_128_ECB:
        case IOTEX_CIPHER_AES_192_ECB:
        case IOTEX_CIPHER_AES_256_ECB:
            return( PSA_KEY_TYPE_AES );

        /* ARIA not yet supported in PSA. */
        /* case IOTEX_CIPHER_ARIA_128_CCM:
           case IOTEX_CIPHER_ARIA_192_CCM:
           case IOTEX_CIPHER_ARIA_256_CCM:
           case IOTEX_CIPHER_ARIA_128_CCM_STAR_NO_TAG:
           case IOTEX_CIPHER_ARIA_192_CCM_STAR_NO_TAG:
           case IOTEX_CIPHER_ARIA_256_CCM_STAR_NO_TAG:
           case IOTEX_CIPHER_ARIA_128_GCM:
           case IOTEX_CIPHER_ARIA_192_GCM:
           case IOTEX_CIPHER_ARIA_256_GCM:
           case IOTEX_CIPHER_ARIA_128_CBC:
           case IOTEX_CIPHER_ARIA_192_CBC:
           case IOTEX_CIPHER_ARIA_256_CBC:
               return( PSA_KEY_TYPE_ARIA ); */

        default:
            return( 0 );
    }
}

static inline psa_algorithm_t iotex_psa_translate_cipher_mode(
    iotex_cipher_mode_t mode, size_t taglen )
{
    switch( mode )
    {
        case IOTEX_MODE_ECB:
            return( PSA_ALG_ECB_NO_PADDING );
        case IOTEX_MODE_GCM:
            return( PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, taglen ) );
        case IOTEX_MODE_CCM:
            return( PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, taglen ) );
        case IOTEX_MODE_CCM_STAR_NO_TAG:
            return PSA_ALG_CCM_STAR_NO_TAG;
        case IOTEX_MODE_CBC:
            if( taglen == 0 )
                return( PSA_ALG_CBC_NO_PADDING );
            else
                return( 0 );
        default:
            return( 0 );
    }
}

static inline psa_key_usage_t iotex_psa_translate_cipher_operation(
    iotex_operation_t op )
{
    switch( op )
    {
        case IOTEX_ENCRYPT:
            return( PSA_KEY_USAGE_ENCRYPT );
        case IOTEX_DECRYPT:
            return( PSA_KEY_USAGE_DECRYPT );
        default:
            return( 0 );
    }
}

/* Translations for hashing. */

static inline psa_algorithm_t iotex_psa_translate_md( iotex_md_type_t md_alg )
{
    switch( md_alg )
    {
#if defined(IOTEX_MD5_C)
    case IOTEX_MD_MD5:
        return( PSA_ALG_MD5 );
#endif
#if defined(IOTEX_SHA1_C)
    case IOTEX_MD_SHA1:
        return( PSA_ALG_SHA_1 );
#endif
#if defined(IOTEX_SHA224_C)
    case IOTEX_MD_SHA224:
        return( PSA_ALG_SHA_224 );
#endif
#if defined(IOTEX_SHA256_C)
    case IOTEX_MD_SHA256:
        return( PSA_ALG_SHA_256 );
#endif
#if defined(IOTEX_SHA384_C)
    case IOTEX_MD_SHA384:
        return( PSA_ALG_SHA_384 );
#endif
#if defined(IOTEX_SHA512_C)
    case IOTEX_MD_SHA512:
        return( PSA_ALG_SHA_512 );
#endif
#if defined(IOTEX_RIPEMD160_C)
    case IOTEX_MD_RIPEMD160:
        return( PSA_ALG_RIPEMD160 );
#endif
    case IOTEX_MD_NONE:
        return( 0 );
    default:
        return( 0 );
    }
}

/* Translations for ECC. */

static inline int iotex_psa_get_ecc_oid_from_id(
    psa_ecc_family_t curve, size_t bits,
    char const **oid, size_t *oid_len )
{
    switch( curve )
    {
        case PSA_ECC_FAMILY_SECP_R1:
            switch( bits )
            {
#if defined(IOTEX_ECP_DP_SECP192R1_ENABLED)
                case 192:
                    *oid = IOTEX_OID_EC_GRP_SECP192R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP192R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP192R1_ENABLED */
#if defined(IOTEX_ECP_DP_SECP224R1_ENABLED)
                case 224:
                    *oid = IOTEX_OID_EC_GRP_SECP224R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP224R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP224R1_ENABLED */
#if defined(IOTEX_ECP_DP_SECP256R1_ENABLED)
                case 256:
                    *oid = IOTEX_OID_EC_GRP_SECP256R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP256R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP256R1_ENABLED */
#if defined(IOTEX_ECP_DP_SECP384R1_ENABLED)
                case 384:
                    *oid = IOTEX_OID_EC_GRP_SECP384R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP384R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP384R1_ENABLED */
#if defined(IOTEX_ECP_DP_SECP521R1_ENABLED)
                case 521:
                    *oid = IOTEX_OID_EC_GRP_SECP521R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP521R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP521R1_ENABLED */
            }
            break;
        case PSA_ECC_FAMILY_SECP_K1:
            switch( bits )
            {
#if defined(IOTEX_ECP_DP_SECP192K1_ENABLED)
                case 192:
                    *oid = IOTEX_OID_EC_GRP_SECP192K1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP192K1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP192K1_ENABLED */
#if defined(IOTEX_ECP_DP_SECP224K1_ENABLED)
                case 224:
                    *oid = IOTEX_OID_EC_GRP_SECP224K1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP224K1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP224K1_ENABLED */
#if defined(IOTEX_ECP_DP_SECP256K1_ENABLED)
                case 256:
                    *oid = IOTEX_OID_EC_GRP_SECP256K1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_SECP256K1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_SECP256K1_ENABLED */
            }
            break;
        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            switch( bits )
            {
#if defined(IOTEX_ECP_DP_BP256R1_ENABLED)
                case 256:
                    *oid = IOTEX_OID_EC_GRP_BP256R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_BP256R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_BP256R1_ENABLED */
#if defined(IOTEX_ECP_DP_BP384R1_ENABLED)
                case 384:
                    *oid = IOTEX_OID_EC_GRP_BP384R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_BP384R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_BP384R1_ENABLED */
#if defined(IOTEX_ECP_DP_BP512R1_ENABLED)
                case 512:
                    *oid = IOTEX_OID_EC_GRP_BP512R1;
                    *oid_len = IOTEX_OID_SIZE( IOTEX_OID_EC_GRP_BP512R1 );
                    return( 0 );
#endif /* IOTEX_ECP_DP_BP512R1_ENABLED */
            }
            break;
    }
    (void) oid;
    (void) oid_len;
    return( -1 );
}

#define IOTEX_PSA_MAX_EC_PUBKEY_LENGTH \
    PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE( PSA_VENDOR_ECC_MAX_CURVE_BITS )

#if defined(IOTEX_ECP_C)
static inline psa_key_type_t iotex_psa_parse_tls_ecc_group(
    uint16_t tls_ecc_grp_reg_id, size_t *bits )
{
    const iotex_ecp_curve_info *curve_info =
        iotex_ecp_curve_info_from_tls_id( tls_ecc_grp_reg_id );
    if( curve_info == NULL )
        return( 0 );
    return( PSA_KEY_TYPE_ECC_KEY_PAIR(
                iotex_ecc_group_to_psa( curve_info->grp_id, bits ) ) );
}
#endif /* IOTEX_ECP_C */

/* Expose whatever RNG the PSA subsystem uses to applications using the
 * iotex_xxx API. The declarations and definitions here need to be
 * consistent with the implementation in library/psa_crypto_random_impl.h.
 * See that file for implementation documentation. */


/* The type of a `f_rng` random generator function that many library functions
 * take.
 *
 * This type name is not part of the Mbed TLS stable API. It may be renamed
 * or moved without warning.
 */
typedef int iotex_f_rng_t( void *p_rng, unsigned char *output, size_t output_size );

#if defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG)

/** The random generator function for the PSA subsystem.
 *
 * This function is suitable as the `f_rng` random generator function
 * parameter of many `iotex_xxx` functions. Use #IOTEX_PSA_RANDOM_STATE
 * to obtain the \p p_rng parameter.
 *
 * The implementation of this function depends on the configuration of the
 * library.
 *
 * \note Depending on the configuration, this may be a function or
 *       a pointer to a function.
 *
 * \note This function may only be used if the PSA crypto subsystem is active.
 *       This means that you must call psa_crypto_init() before any call to
 *       this function, and you must not call this function after calling
 *       iotex_psa_crypto_free().
 *
 * \param p_rng         The random generator context. This must be
 *                      #IOTEX_PSA_RANDOM_STATE. No other state is
 *                      supported.
 * \param output        The buffer to fill. It must have room for
 *                      \c output_size bytes.
 * \param output_size   The number of bytes to write to \p output.
 *                      This function may fail if \p output_size is too
 *                      large. It is guaranteed to accept any output size
 *                      requested by Mbed TLS library functions. The
 *                      maximum request size depends on the library
 *                      configuration.
 *
 * \return              \c 0 on success.
 * \return              An `IOTEX_ERR_ENTROPY_xxx`,
 *                      `IOTEX_ERR_PLATFORM_xxx,
 *                      `IOTEX_ERR_CTR_DRBG_xxx` or
 *                      `IOTEX_ERR_HMAC_DRBG_xxx` on error.
 */
int iotex_psa_get_random( void *p_rng,
                            unsigned char *output,
                            size_t output_size );

/** The random generator state for the PSA subsystem.
 *
 * This macro expands to an expression which is suitable as the `p_rng`
 * random generator state parameter of many `iotex_xxx` functions.
 * It must be used in combination with the random generator function
 * iotex_psa_get_random().
 *
 * The implementation of this macro depends on the configuration of the
 * library. Do not make any assumption on its nature.
 */
#define IOTEX_PSA_RANDOM_STATE NULL

#else /* !defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG) */

#if defined(IOTEX_CTR_DRBG_C)
#include "include/ctr_drbg.h"
typedef iotex_ctr_drbg_context iotex_psa_drbg_context_t;
static iotex_f_rng_t *const iotex_psa_get_random = iotex_ctr_drbg_random;
#elif defined(IOTEX_HMAC_DRBG_C)
#include "include/hmac_drbg.h"
typedef iotex_hmac_drbg_context iotex_psa_drbg_context_t;
static iotex_f_rng_t *const iotex_psa_get_random = iotex_hmac_drbg_random;
#endif
extern iotex_psa_drbg_context_t *const iotex_psa_random_state;

#define IOTEX_PSA_RANDOM_STATE iotex_psa_random_state

#endif /* !defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG) */

#endif /* IOTEX_PSA_CRYPTO_C */

#endif /* IOTEX_PSA_UTIL_H */
