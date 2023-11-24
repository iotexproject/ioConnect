#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#include "include/iotex/build_info.h"

#include "include/iotex/cmac.h"
#include "include/iotex/gcm.h"
#include "include/iotex/ccm.h"
#include "include/iotex/chachapoly.h"

/* Include the context definition for the compiled-in drivers for the primitive
 * algorithms. */
#include "include/server/crypto_driver_contexts_primitives.h"

struct psa_hash_operation_s
{
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_driver_wrappers.h.
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. the driver context is not active, in use). */
    unsigned int id;
    psa_driver_hash_context_t ctx;
};

#define PSA_HASH_OPERATION_INIT { 0, { 0 } }
static inline struct psa_hash_operation_s psa_hash_operation_init( void )
{
    const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
    return( v );
}

struct psa_cipher_operation_s
{
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int id;

    unsigned int iv_required : 1;
    unsigned int iv_set : 1;

    uint8_t default_iv_length;

    psa_driver_cipher_context_t ctx;
};

#define PSA_CIPHER_OPERATION_INIT { 0, 0, 0, 0, { 0 } }
static inline struct psa_cipher_operation_s psa_cipher_operation_init( void )
{
    const struct psa_cipher_operation_s v = PSA_CIPHER_OPERATION_INIT;
    return( v );
}

/* Include the context definition for the compiled-in drivers for the composite
 * algorithms. */
#include "include/server/crypto_driver_contexts_composites.h"

struct psa_mac_operation_s
{
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int id;
    uint8_t mac_size;
    unsigned int is_sign : 1;
    psa_driver_mac_context_t ctx;
};

#define PSA_MAC_OPERATION_INIT { 0, 0, 0, { 0 } }
static inline struct psa_mac_operation_s psa_mac_operation_init( void )
{
    const struct psa_mac_operation_s v = PSA_MAC_OPERATION_INIT;
    return( v );
}

struct psa_aead_operation_s
{

    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int id;

    psa_algorithm_t alg;
    psa_key_type_t key_type;

    size_t ad_remaining;
    size_t body_remaining;

    unsigned int nonce_set : 1;
    unsigned int lengths_set : 1;
    unsigned int ad_started : 1;
    unsigned int body_started : 1;
    unsigned int is_encrypt : 1;

    psa_driver_aead_context_t ctx;
};

#define PSA_AEAD_OPERATION_INIT {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0}}
static inline struct psa_aead_operation_s psa_aead_operation_init( void )
{
    const struct psa_aead_operation_s v = PSA_AEAD_OPERATION_INIT;
    return( v );
}

#if defined(IOTEX_PSA_BUILTIN_ALG_HKDF) || \
    defined(IOTEX_PSA_BUILTIN_ALG_HKDF_EXTRACT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_HKDF_EXPAND)
typedef struct
{
    uint8_t *info;
    size_t info_length;
#if PSA_HASH_MAX_SIZE > 0xff
#error "PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif
    uint8_t offset_in_block;
    uint8_t block_number;
    unsigned int state : 2;
    unsigned int info_set : 1;
    uint8_t output_block[PSA_HASH_MAX_SIZE];
    uint8_t prk[PSA_HASH_MAX_SIZE];
    struct psa_mac_operation_s (hmac);
} psa_hkdf_key_derivation_t;
#endif /* IOTEX_PSA_BUILTIN_ALG_HKDF ||
          IOTEX_PSA_BUILTIN_ALG_HKDF_EXTRACT ||
          IOTEX_PSA_BUILTIN_ALG_HKDF_EXPAND */

#if defined(IOTEX_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(IOTEX_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
typedef enum
{
    PSA_TLS12_PRF_STATE_INIT,             /* no input provided */
    PSA_TLS12_PRF_STATE_SEED_SET,         /* seed has been set */
    PSA_TLS12_PRF_STATE_OTHER_KEY_SET,    /* other key has been set - optional */
    PSA_TLS12_PRF_STATE_KEY_SET,          /* key has been set */
    PSA_TLS12_PRF_STATE_LABEL_SET,        /* label has been set */
    PSA_TLS12_PRF_STATE_OUTPUT            /* output has been started */
} psa_tls12_prf_key_derivation_state_t;

typedef struct psa_tls12_prf_key_derivation_s
{
#if PSA_HASH_MAX_SIZE > 0xff
#error "PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif

    /* Indicates how many bytes in the current HMAC block have
     * not yet been read by the user. */
    uint8_t left_in_block;

    /* The 1-based number of the block. */
    uint8_t block_number;

    psa_tls12_prf_key_derivation_state_t (state);

    uint8_t *secret;
    size_t secret_length;
    uint8_t *seed;
    size_t seed_length;
    uint8_t *label;
    size_t label_length;
#if defined(IOTEX_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    uint8_t *other_secret;
    size_t other_secret_length;
#endif /* IOTEX_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

    uint8_t (Ai)[PSA_HASH_MAX_SIZE];

    /* `HMAC_hash( prk, A( i ) + seed )` in the notation of RFC 5246, Sect. 5. */
    uint8_t (output_block)[PSA_HASH_MAX_SIZE];
} psa_tls12_prf_key_derivation_t;
#endif /* IOTEX_PSA_BUILTIN_ALG_TLS12_PRF) ||
        * IOTEX_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

struct psa_key_derivation_s
{
    psa_algorithm_t alg;
    unsigned int can_output_key : 1;
    size_t capacity;
    union
    {
        /* Make the union non-empty even with no supported algorithms. */
        uint8_t dummy;
#if defined(IOTEX_PSA_BUILTIN_ALG_HKDF) || \
    defined(IOTEX_PSA_BUILTIN_ALG_HKDF_EXTRACT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_HKDF_EXPAND)
        psa_hkdf_key_derivation_t hkdf;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(IOTEX_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
        psa_tls12_prf_key_derivation_t tls12_prf;
#endif
    } ctx;
};

/* This only zeroes out the first byte in the union, the rest is unspecified. */
#define PSA_KEY_DERIVATION_OPERATION_INIT { 0, 0, 0, { 0 } }
static inline struct psa_key_derivation_s psa_key_derivation_operation_init(
        void )
{
    const struct psa_key_derivation_s v = PSA_KEY_DERIVATION_OPERATION_INIT;
    return( v );
}

struct psa_key_policy_s
{
    psa_key_usage_t usage;
    psa_algorithm_t alg;
    psa_algorithm_t alg2;
};
typedef struct psa_key_policy_s psa_key_policy_t;

#define PSA_KEY_POLICY_INIT { 0, 0, 0 }
static inline struct psa_key_policy_s psa_key_policy_init( void )
{
    const struct psa_key_policy_s v = PSA_KEY_POLICY_INIT;
    return( v );
}

/* The type used internally for key sizes.
 * Public interfaces use size_t, but internally we use a smaller type. */
typedef uint16_t psa_key_bits_t;
/* The maximum value of the type used to represent bit-sizes.
 * This is used to mark an invalid key size. */
#define PSA_KEY_BITS_TOO_LARGE          ( ( psa_key_bits_t ) -1 )
/* The maximum size of a key in bits.
 * Currently defined as the maximum that can be represented, rounded down
 * to a whole number of bytes.
 * This is an uncast value so that it can be used in preprocessor
 * conditionals. */
#define PSA_MAX_KEY_BITS 0xfff8

/** A mask of flags that can be stored in key attributes.
 *
 * This type is also used internally to store flags in slots. Internal
 * flags are defined in library/psa_crypto_core.h. Internal flags may have
 * the same value as external flags if they are properly handled during
 * key creation and in psa_get_key_attributes.
 */
typedef uint16_t psa_key_attributes_flag_t;

#define IOTEX_PSA_KA_FLAG_HAS_SLOT_NUMBER     \
    ( (psa_key_attributes_flag_t) 0x0001 )

/* A mask of key attribute flags used externally only.
 * Only meant for internal checks inside the library. */
#define IOTEX_PSA_KA_MASK_EXTERNAL_ONLY (      \
        IOTEX_PSA_KA_FLAG_HAS_SLOT_NUMBER |    \
        0 )

/* A mask of key attribute flags used both internally and externally.
 * Currently there aren't any. */
#define IOTEX_PSA_KA_MASK_DUAL_USE (          \
        0 )

typedef struct
{
    psa_key_type_t type;
    psa_key_bits_t bits;
    psa_key_lifetime_t lifetime;
    psa_key_id_t id;
    psa_key_policy_t policy;
    psa_key_attributes_flag_t flags;
} psa_core_key_attributes_t;

#define PSA_CORE_KEY_ATTRIBUTES_INIT { PSA_KEY_TYPE_NONE, 0,            \
                                       PSA_KEY_LIFETIME_VOLATILE,       \
                                       IOTEX_SVC_KEY_ID_INIT,         \
                                       PSA_KEY_POLICY_INIT, 0 }

struct psa_key_attributes_s
{
    psa_core_key_attributes_t core;
#if defined(IOTEX_PSA_CRYPTO_SE_C)
    psa_key_slot_number_t slot_number;
#endif /* IOTEX_PSA_CRYPTO_SE_C */
    void *domain_parameters;
    size_t domain_parameters_size;
};

#if defined(IOTEX_PSA_CRYPTO_SE_C)
#define PSA_KEY_ATTRIBUTES_INIT { PSA_CORE_KEY_ATTRIBUTES_INIT, 0, NULL, 0 }
#else
#define PSA_KEY_ATTRIBUTES_INIT { PSA_CORE_KEY_ATTRIBUTES_INIT, NULL, 0 }
#endif

static inline struct psa_key_attributes_s psa_key_attributes_init( void )
{
    const struct psa_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
    return( v );
}

static inline void psa_set_key_id( psa_key_attributes_t *attributes,
                                   psa_key_id_t key )
{
    psa_key_lifetime_t lifetime = attributes->core.lifetime;

    attributes->core.id = key;

    if( PSA_KEY_LIFETIME_IS_VOLATILE( lifetime ) )
    {
        attributes->core.lifetime =
            PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                PSA_KEY_LIFETIME_PERSISTENT,
                PSA_KEY_LIFETIME_GET_LOCATION( lifetime ) );
    }
}

static inline psa_key_id_t psa_get_key_id(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.id );
}

static inline void psa_set_key_lifetime( psa_key_attributes_t *attributes,
                                        psa_key_lifetime_t lifetime )
{
    attributes->core.lifetime = lifetime;
    if( PSA_KEY_LIFETIME_IS_VOLATILE( lifetime ) )
    {
        attributes->core.id = 0;
    }
}

static inline psa_key_lifetime_t psa_get_key_lifetime(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.lifetime );
}

static inline void psa_extend_key_usage_flags( psa_key_usage_t *usage_flags )
{
    if( *usage_flags & PSA_KEY_USAGE_SIGN_HASH )
        *usage_flags |= PSA_KEY_USAGE_SIGN_MESSAGE;

    if( *usage_flags & PSA_KEY_USAGE_VERIFY_HASH )
        *usage_flags |= PSA_KEY_USAGE_VERIFY_MESSAGE;
}

static inline void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
                                           psa_key_usage_t usage_flags)
{
    psa_extend_key_usage_flags( &usage_flags );
    attributes->core.policy.usage = usage_flags;
}

static inline psa_key_usage_t psa_get_key_usage_flags(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.policy.usage );
}

static inline void psa_set_key_algorithm( psa_key_attributes_t *attributes,
                                         psa_algorithm_t alg )
{
    attributes->core.policy.alg = alg;
}

static inline psa_algorithm_t psa_get_key_algorithm(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.policy.alg );
}

/* This function is declared in crypto_extra.h, which comes after this
 * header file, but we need the function here, so repeat the declaration. */
psa_status_t psa_set_key_domain_parameters( psa_key_attributes_t *attributes,
                                           psa_key_type_t type,
                                           const uint8_t *data,
                                           size_t data_length );

static inline void psa_set_key_type( psa_key_attributes_t *attributes,
                                    psa_key_type_t type )
{
    if( attributes->domain_parameters == NULL )
    {
        /* Common case: quick path */
        attributes->core.type = type;
    }
    else
    {
        /* Call the bigger function to free the old domain parameters.
         * Ignore any errors which may arise due to type requiring
         * non-default domain parameters, since this function can't
         * report errors. */
        (void) psa_set_key_domain_parameters( attributes, type, NULL, 0 );
    }
}

static inline psa_key_type_t psa_get_key_type(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.type );
}

static inline void psa_set_key_bits( psa_key_attributes_t *attributes,
                                    size_t bits )
{
    if( bits > PSA_MAX_KEY_BITS )
        attributes->core.bits = PSA_KEY_BITS_TOO_LARGE;
    else
        attributes->core.bits = (psa_key_bits_t) bits;
}

static inline size_t psa_get_key_bits(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.bits );
}

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_STRUCT_H */
