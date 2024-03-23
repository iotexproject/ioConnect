#ifndef IOTEX_CIPHER_H
#define IOTEX_CIPHER_H

#include "include/iotex/build_info.h"

#include <stddef.h>
#include "include/iotex/platform_util.h"

#if defined(IOTEX_GCM_C) || defined(IOTEX_CCM_C) || defined(IOTEX_CHACHAPOLY_C)
#define IOTEX_CIPHER_MODE_AEAD
#endif

#if defined(IOTEX_CIPHER_MODE_CBC)
#define IOTEX_CIPHER_MODE_WITH_PADDING
#endif

#if defined(IOTEX_CIPHER_NULL_CIPHER) || \
    defined(IOTEX_CHACHA20_C)
#define IOTEX_CIPHER_MODE_STREAM
#endif

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/** The selected feature is not available. */
#define IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE  -0x6080
/** Bad input parameters. */
#define IOTEX_ERR_CIPHER_BAD_INPUT_DATA       -0x6100
/** Failed to allocate memory. */
#define IOTEX_ERR_CIPHER_ALLOC_FAILED         -0x6180
/** Input data contains invalid padding and is rejected. */
#define IOTEX_ERR_CIPHER_INVALID_PADDING      -0x6200
/** Decryption of block requires a full block. */
#define IOTEX_ERR_CIPHER_FULL_BLOCK_EXPECTED  -0x6280
/** Authentication failed (for AEAD modes). */
#define IOTEX_ERR_CIPHER_AUTH_FAILED          -0x6300
/** The context is invalid. For example, because it was freed. */
#define IOTEX_ERR_CIPHER_INVALID_CONTEXT      -0x6380

#define IOTEX_CIPHER_VARIABLE_IV_LEN     0x01    /**< Cipher accepts IVs of variable length. */
#define IOTEX_CIPHER_VARIABLE_KEY_LEN    0x02    /**< Cipher accepts keys of variable length. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    IOTEX_CIPHER_PSA_KEY_UNSET = 0,
    IOTEX_CIPHER_PSA_KEY_OWNED, /* Used for PSA-based cipher contexts which */
                                  /* use raw key material internally imported */
                                  /* as a volatile key, and which hence need  */
                                  /* to destroy that key when the context is  */
                                  /* freed.                                   */
    IOTEX_CIPHER_PSA_KEY_NOT_OWNED, /* Used for PSA-based cipher contexts   */
                                      /* which use a key provided by the      */
                                      /* user, and which hence will not be    */
                                      /* destroyed when the context is freed. */
} iotex_cipher_psa_key_ownership;

typedef struct
{
    unsigned int alg;
    unsigned int slot;
    iotex_cipher_psa_key_ownership slot_state;
} iotex_cipher_context_psa;

/**
 * \brief     Supported cipher types.
 *
 * \warning   DES is considered weak cipher and its use
 *            constitutes a security risk. Arm recommends considering stronger
 *            ciphers instead.
 */
typedef enum {
    IOTEX_CIPHER_ID_NONE = 0,  /**< Placeholder to mark the end of cipher ID lists. */
    IOTEX_CIPHER_ID_NULL,      /**< The identity cipher, treated as a stream cipher. */
    IOTEX_CIPHER_ID_AES,       /**< The AES cipher. */
    IOTEX_CIPHER_ID_DES,       /**< The DES cipher. */
    IOTEX_CIPHER_ID_3DES,      /**< The Triple DES cipher. */
    IOTEX_CIPHER_ID_CAMELLIA,  /**< The Camellia cipher. */
    IOTEX_CIPHER_ID_ARIA,      /**< The Aria cipher. */
    IOTEX_CIPHER_ID_CHACHA20,  /**< The ChaCha20 cipher. */
} iotex_cipher_id_t;

/**
 * \brief     Supported {cipher type, cipher mode} pairs.
 *
 * \warning   DES is considered weak cipher and its use
 *            constitutes a security risk. Arm recommends considering stronger
 *            ciphers instead.
 */
typedef enum {
    IOTEX_CIPHER_NONE = 0,             /**< Placeholder to mark the end of cipher-pair lists. */
    IOTEX_CIPHER_NULL,                 /**< The identity stream cipher. */
    IOTEX_CIPHER_AES_128_ECB,          /**< AES cipher with 128-bit ECB mode. */
    IOTEX_CIPHER_AES_192_ECB,          /**< AES cipher with 192-bit ECB mode. */
    IOTEX_CIPHER_AES_256_ECB,          /**< AES cipher with 256-bit ECB mode. */
    IOTEX_CIPHER_AES_128_CBC,          /**< AES cipher with 128-bit CBC mode. */
    IOTEX_CIPHER_AES_192_CBC,          /**< AES cipher with 192-bit CBC mode. */
    IOTEX_CIPHER_AES_256_CBC,          /**< AES cipher with 256-bit CBC mode. */
    IOTEX_CIPHER_AES_128_CFB128,       /**< AES cipher with 128-bit CFB128 mode. */
    IOTEX_CIPHER_AES_192_CFB128,       /**< AES cipher with 192-bit CFB128 mode. */
    IOTEX_CIPHER_AES_256_CFB128,       /**< AES cipher with 256-bit CFB128 mode. */
    IOTEX_CIPHER_AES_128_CTR,          /**< AES cipher with 128-bit CTR mode. */
    IOTEX_CIPHER_AES_192_CTR,          /**< AES cipher with 192-bit CTR mode. */
    IOTEX_CIPHER_AES_256_CTR,          /**< AES cipher with 256-bit CTR mode. */
    IOTEX_CIPHER_AES_128_GCM,          /**< AES cipher with 128-bit GCM mode. */
    IOTEX_CIPHER_AES_192_GCM,          /**< AES cipher with 192-bit GCM mode. */
    IOTEX_CIPHER_AES_256_GCM,          /**< AES cipher with 256-bit GCM mode. */
    IOTEX_CIPHER_CAMELLIA_128_ECB,     /**< Camellia cipher with 128-bit ECB mode. */
    IOTEX_CIPHER_CAMELLIA_192_ECB,     /**< Camellia cipher with 192-bit ECB mode. */
    IOTEX_CIPHER_CAMELLIA_256_ECB,     /**< Camellia cipher with 256-bit ECB mode. */
    IOTEX_CIPHER_CAMELLIA_128_CBC,     /**< Camellia cipher with 128-bit CBC mode. */
    IOTEX_CIPHER_CAMELLIA_192_CBC,     /**< Camellia cipher with 192-bit CBC mode. */
    IOTEX_CIPHER_CAMELLIA_256_CBC,     /**< Camellia cipher with 256-bit CBC mode. */
    IOTEX_CIPHER_CAMELLIA_128_CFB128,  /**< Camellia cipher with 128-bit CFB128 mode. */
    IOTEX_CIPHER_CAMELLIA_192_CFB128,  /**< Camellia cipher with 192-bit CFB128 mode. */
    IOTEX_CIPHER_CAMELLIA_256_CFB128,  /**< Camellia cipher with 256-bit CFB128 mode. */
    IOTEX_CIPHER_CAMELLIA_128_CTR,     /**< Camellia cipher with 128-bit CTR mode. */
    IOTEX_CIPHER_CAMELLIA_192_CTR,     /**< Camellia cipher with 192-bit CTR mode. */
    IOTEX_CIPHER_CAMELLIA_256_CTR,     /**< Camellia cipher with 256-bit CTR mode. */
    IOTEX_CIPHER_CAMELLIA_128_GCM,     /**< Camellia cipher with 128-bit GCM mode. */
    IOTEX_CIPHER_CAMELLIA_192_GCM,     /**< Camellia cipher with 192-bit GCM mode. */
    IOTEX_CIPHER_CAMELLIA_256_GCM,     /**< Camellia cipher with 256-bit GCM mode. */
    IOTEX_CIPHER_DES_ECB,              /**< DES cipher with ECB mode. */
    IOTEX_CIPHER_DES_CBC,              /**< DES cipher with CBC mode. */
    IOTEX_CIPHER_DES_EDE_ECB,          /**< DES cipher with EDE ECB mode. */
    IOTEX_CIPHER_DES_EDE_CBC,          /**< DES cipher with EDE CBC mode. */
    IOTEX_CIPHER_DES_EDE3_ECB,         /**< DES cipher with EDE3 ECB mode. */
    IOTEX_CIPHER_DES_EDE3_CBC,         /**< DES cipher with EDE3 CBC mode. */
    IOTEX_CIPHER_AES_128_CCM,          /**< AES cipher with 128-bit CCM mode. */
    IOTEX_CIPHER_AES_192_CCM,          /**< AES cipher with 192-bit CCM mode. */
    IOTEX_CIPHER_AES_256_CCM,          /**< AES cipher with 256-bit CCM mode. */
    IOTEX_CIPHER_AES_128_CCM_STAR_NO_TAG, /**< AES cipher with 128-bit CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_AES_192_CCM_STAR_NO_TAG, /**< AES cipher with 192-bit CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_AES_256_CCM_STAR_NO_TAG, /**< AES cipher with 256-bit CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_CAMELLIA_128_CCM,     /**< Camellia cipher with 128-bit CCM mode. */
    IOTEX_CIPHER_CAMELLIA_192_CCM,     /**< Camellia cipher with 192-bit CCM mode. */
    IOTEX_CIPHER_CAMELLIA_256_CCM,     /**< Camellia cipher with 256-bit CCM mode. */
    IOTEX_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG, /**< Camellia cipher with 128-bit CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG, /**< Camellia cipher with 192-bit CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG, /**< Camellia cipher with 256-bit CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_ARIA_128_ECB,         /**< Aria cipher with 128-bit key and ECB mode. */
    IOTEX_CIPHER_ARIA_192_ECB,         /**< Aria cipher with 192-bit key and ECB mode. */
    IOTEX_CIPHER_ARIA_256_ECB,         /**< Aria cipher with 256-bit key and ECB mode. */
    IOTEX_CIPHER_ARIA_128_CBC,         /**< Aria cipher with 128-bit key and CBC mode. */
    IOTEX_CIPHER_ARIA_192_CBC,         /**< Aria cipher with 192-bit key and CBC mode. */
    IOTEX_CIPHER_ARIA_256_CBC,         /**< Aria cipher with 256-bit key and CBC mode. */
    IOTEX_CIPHER_ARIA_128_CFB128,      /**< Aria cipher with 128-bit key and CFB-128 mode. */
    IOTEX_CIPHER_ARIA_192_CFB128,      /**< Aria cipher with 192-bit key and CFB-128 mode. */
    IOTEX_CIPHER_ARIA_256_CFB128,      /**< Aria cipher with 256-bit key and CFB-128 mode. */
    IOTEX_CIPHER_ARIA_128_CTR,         /**< Aria cipher with 128-bit key and CTR mode. */
    IOTEX_CIPHER_ARIA_192_CTR,         /**< Aria cipher with 192-bit key and CTR mode. */
    IOTEX_CIPHER_ARIA_256_CTR,         /**< Aria cipher with 256-bit key and CTR mode. */
    IOTEX_CIPHER_ARIA_128_GCM,         /**< Aria cipher with 128-bit key and GCM mode. */
    IOTEX_CIPHER_ARIA_192_GCM,         /**< Aria cipher with 192-bit key and GCM mode. */
    IOTEX_CIPHER_ARIA_256_GCM,         /**< Aria cipher with 256-bit key and GCM mode. */
    IOTEX_CIPHER_ARIA_128_CCM,         /**< Aria cipher with 128-bit key and CCM mode. */
    IOTEX_CIPHER_ARIA_192_CCM,         /**< Aria cipher with 192-bit key and CCM mode. */
    IOTEX_CIPHER_ARIA_256_CCM,         /**< Aria cipher with 256-bit key and CCM mode. */
    IOTEX_CIPHER_ARIA_128_CCM_STAR_NO_TAG, /**< Aria cipher with 128-bit key and CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_ARIA_192_CCM_STAR_NO_TAG, /**< Aria cipher with 192-bit key and CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_ARIA_256_CCM_STAR_NO_TAG, /**< Aria cipher with 256-bit key and CCM_STAR_NO_TAG mode. */
    IOTEX_CIPHER_AES_128_OFB,          /**< AES 128-bit cipher in OFB mode. */
    IOTEX_CIPHER_AES_192_OFB,          /**< AES 192-bit cipher in OFB mode. */
    IOTEX_CIPHER_AES_256_OFB,          /**< AES 256-bit cipher in OFB mode. */
    IOTEX_CIPHER_AES_128_XTS,          /**< AES 128-bit cipher in XTS block mode. */
    IOTEX_CIPHER_AES_256_XTS,          /**< AES 256-bit cipher in XTS block mode. */
    IOTEX_CIPHER_CHACHA20,             /**< ChaCha20 stream cipher. */
    IOTEX_CIPHER_CHACHA20_POLY1305,    /**< ChaCha20-Poly1305 AEAD cipher. */
    IOTEX_CIPHER_AES_128_KW,           /**< AES cipher with 128-bit NIST KW mode. */
    IOTEX_CIPHER_AES_192_KW,           /**< AES cipher with 192-bit NIST KW mode. */
    IOTEX_CIPHER_AES_256_KW,           /**< AES cipher with 256-bit NIST KW mode. */
    IOTEX_CIPHER_AES_128_KWP,          /**< AES cipher with 128-bit NIST KWP mode. */
    IOTEX_CIPHER_AES_192_KWP,          /**< AES cipher with 192-bit NIST KWP mode. */
    IOTEX_CIPHER_AES_256_KWP,          /**< AES cipher with 256-bit NIST KWP mode. */
} iotex_cipher_type_t;

/** Supported cipher modes. */
typedef enum {
    IOTEX_MODE_NONE = 0,               /**< None.                        */
    IOTEX_MODE_ECB,                    /**< The ECB cipher mode.         */
    IOTEX_MODE_CBC,                    /**< The CBC cipher mode.         */
    IOTEX_MODE_CFB,                    /**< The CFB cipher mode.         */
    IOTEX_MODE_OFB,                    /**< The OFB cipher mode.         */
    IOTEX_MODE_CTR,                    /**< The CTR cipher mode.         */
    IOTEX_MODE_GCM,                    /**< The GCM cipher mode.         */
    IOTEX_MODE_STREAM,                 /**< The stream cipher mode.      */
    IOTEX_MODE_CCM,                    /**< The CCM cipher mode.         */
    IOTEX_MODE_CCM_STAR_NO_TAG,        /**< The CCM*-no-tag cipher mode. */
    IOTEX_MODE_XTS,                    /**< The XTS cipher mode.         */
    IOTEX_MODE_CHACHAPOLY,             /**< The ChaCha-Poly cipher mode. */
    IOTEX_MODE_KW,                     /**< The SP800-38F KW mode */
    IOTEX_MODE_KWP,                    /**< The SP800-38F KWP mode */
} iotex_cipher_mode_t;

/** Supported cipher padding types. */
typedef enum {
    IOTEX_PADDING_PKCS7 = 0,     /**< PKCS7 padding (default).        */
    IOTEX_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
    IOTEX_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
    IOTEX_PADDING_ZEROS,         /**< Zero padding (not reversible). */
    IOTEX_PADDING_NONE,          /**< Never pad (full blocks only).   */
} iotex_cipher_padding_t;

/** Type of operation. */
typedef enum {
    IOTEX_OPERATION_NONE = -1,
    IOTEX_DECRYPT = 0,
    IOTEX_ENCRYPT,
} iotex_operation_t;

enum {
    /** Undefined key length. */
    IOTEX_KEY_LENGTH_NONE = 0,
    /** Key length, in bits (including parity), for DES keys. */
    IOTEX_KEY_LENGTH_DES  = 64,
    /** Key length in bits, including parity, for DES in two-key EDE. */
    IOTEX_KEY_LENGTH_DES_EDE = 128,
    /** Key length in bits, including parity, for DES in three-key EDE. */
    IOTEX_KEY_LENGTH_DES_EDE3 = 192,
};

/** Maximum length of any IV, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with IOTEX_SSL_MAX_IV_LENGTH defined
 * in library/ssl_misc.h. */
#define IOTEX_MAX_IV_LENGTH      16

/** Maximum block size of any cipher, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with IOTEX_SSL_MAX_BLOCK_LENGTH defined
 * in library/ssl_misc.h. */
#define IOTEX_MAX_BLOCK_LENGTH   16

/** Maximum key length, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * For now, only check whether XTS is enabled which uses 64 Byte keys,
 * and use 32 Bytes as an upper bound for the maximum key length otherwise.
 * This should be kept in sync with IOTEX_SSL_MAX_BLOCK_LENGTH defined
 * in library/ssl_misc.h, which however deliberately ignores the case of XTS
 * since the latter isn't used in SSL/TLS. */
#if defined(IOTEX_CIPHER_MODE_XTS)
#define IOTEX_MAX_KEY_LENGTH     64
#else
#define IOTEX_MAX_KEY_LENGTH     32
#endif /* IOTEX_CIPHER_MODE_XTS */

/**
 * Base cipher information (opaque struct).
 */
typedef struct iotex_cipher_base_t iotex_cipher_base_t;

/**
 * CMAC context (opaque struct).
 */
typedef struct iotex_cmac_context_t iotex_cmac_context_t;

/**
 * Cipher information. Allows calling cipher functions
 * in a generic way.
 *
 * \note        The library does not support custom cipher info structures,
 *              only built-in structures returned by the functions
 *              iotex_cipher_info_from_string(),
 *              iotex_cipher_info_from_type(),
 *              iotex_cipher_info_from_values(),
 *              iotex_cipher_info_from_psa().
 */
typedef struct iotex_cipher_info_t
{
    /** Full cipher identifier. For example,
     * IOTEX_CIPHER_AES_256_CBC.
     */
    iotex_cipher_type_t type;

    /** The cipher mode. For example, IOTEX_MODE_CBC. */
    iotex_cipher_mode_t mode;

    /** The cipher key length, in bits. This is the
     * default length for variable sized ciphers.
     * Includes parity bits for ciphers like DES.
     */
    unsigned int key_bitlen;

    /** Name of the cipher. */
    const char * name;

    /** IV or nonce size, in Bytes.
     * For ciphers that accept variable IV sizes,
     * this is the recommended size.
     */
    unsigned int iv_size;

    /** Bitflag comprised of IOTEX_CIPHER_VARIABLE_IV_LEN and
     *  IOTEX_CIPHER_VARIABLE_KEY_LEN indicating whether the
     *  cipher supports variable IV or variable key sizes, respectively.
     */
    int flags;

    /** The block size, in Bytes. */
    unsigned int block_size;

    /** Struct for base cipher information and functions. */
    const iotex_cipher_base_t *base;

} iotex_cipher_info_t;

/**
 * Generic cipher context.
 */
typedef struct iotex_cipher_context_t
{
    /** Information about the associated cipher. */
//    const iotex_cipher_info_t *cipher_info;
    iotex_cipher_info_t *cipher_info;

    /** Key length to use. */
    int key_bitlen;

    /** Operation that the key of the context has been
     * initialized for.
     */
    iotex_operation_t operation;

#if defined(IOTEX_CIPHER_MODE_WITH_PADDING)
    /** Padding functions to use, if relevant for
     * the specific cipher mode.
     */
    void (*add_padding)( unsigned char *output, size_t olen, size_t data_len );
    int (*get_padding)( unsigned char *input, size_t ilen, size_t *data_len );
#endif

    /** Buffer for input that has not been processed yet. */
    unsigned char unprocessed_data[IOTEX_MAX_BLOCK_LENGTH];

    /** Number of Bytes that have not been processed yet. */
    size_t unprocessed_len;

    /** Current IV or NONCE_COUNTER for CTR-mode, data unit (or sector) number
     * for XTS-mode. */
    unsigned char iv[IOTEX_MAX_IV_LENGTH];

    /** IV size in Bytes, for ciphers with variable-length IVs. */
    size_t iv_size;

    /** The cipher-specific context. */
    void *cipher_ctx;

#if defined(IOTEX_CMAC_C)
    /** CMAC-specific context. */
    iotex_cmac_context_t *cmac_ctx;
#endif

#if defined(IOTEX_USE_PSA_CRYPTO)
    /** Indicates whether the cipher operations should be performed
     *  by Mbed TLS' own crypto library or an external implementation
     *  of the PSA Crypto API.
     *  This is unset if the cipher context was established through
     *  iotex_cipher_setup(), and set if it was established through
     *  iotex_cipher_setup_psa().
     */
    unsigned char psa_enabled;
#endif /* IOTEX_USE_PSA_CRYPTO */

} iotex_cipher_context_t;

/**
 * \brief This function retrieves the list of ciphers supported
 *        by the generic cipher module.
 *
 *        For any cipher identifier in the returned list, you can
 *        obtain the corresponding generic cipher information structure
 *        via iotex_cipher_info_from_type(), which can then be used
 *        to prepare a cipher context via iotex_cipher_setup().
 *
 *
 * \return      A statically-allocated array of cipher identifiers
 *              of type cipher_type_t. The last entry is zero.
 */
const int *iotex_cipher_list( void );

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher name.
 *
 * \param cipher_name   Name of the cipher to search for. This must not be
 *                      \c NULL.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_name.
 * \return              \c NULL if the associated cipher information is not found.
 */
const iotex_cipher_info_t *iotex_cipher_info_from_string( const char *cipher_name );

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher type.
 *
 * \param cipher_type   Type of the cipher to search for.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_type.
 * \return              \c NULL if the associated cipher information is not found.
 */
const iotex_cipher_info_t *iotex_cipher_info_from_type( const iotex_cipher_type_t cipher_type );

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher ID,
 *                      key size and mode.
 *
 * \param cipher_id     The ID of the cipher to search for. For example,
 *                      #IOTEX_CIPHER_ID_AES.
 * \param key_bitlen    The length of the key in bits.
 * \param mode          The cipher mode. For example, #IOTEX_MODE_CBC.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_id.
 * \return              \c NULL if the associated cipher information is not found.
 */
const iotex_cipher_info_t *iotex_cipher_info_from_values( const iotex_cipher_id_t cipher_id,
                                              int key_bitlen,
                                              const iotex_cipher_mode_t mode );

/**
 * \brief               Retrieve the identifier for a cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The full cipher identifier (\c IOTEX_CIPHER_xxx).
 * \return              #IOTEX_CIPHER_NONE if \p info is \c NULL.
 */
static inline iotex_cipher_type_t iotex_cipher_info_get_type(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( IOTEX_CIPHER_NONE );
    else
        return( info->type );
}

/**
 * \brief               Retrieve the operation mode for a cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The cipher mode (\c IOTEX_MODE_xxx).
 * \return              #IOTEX_MODE_NONE if \p info is \c NULL.
 */
static inline iotex_cipher_mode_t iotex_cipher_info_get_mode(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( IOTEX_MODE_NONE );
    else
        return( info->mode );
}

/**
 * \brief               Retrieve the key size for a cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The key length in bits.
 *                      For variable-sized ciphers, this is the default length.
 *                      For DES, this includes the parity bits.
 * \return              \c 0 if \p info is \c NULL.
 */
static inline size_t iotex_cipher_info_get_key_bitlen(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( 0 );
    else
        return( info->key_bitlen );
}

/**
 * \brief               Retrieve the human-readable name for a
 *                      cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The cipher name, which is a human readable string,
 *                      with static storage duration.
 * \return              \c NULL if \c info is \p NULL.
 */
static inline const char *iotex_cipher_info_get_name(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( NULL );
    else
        return( info->name );
}

/**
 * \brief       This function returns the size of the IV or nonce
 *              for the cipher info structure, in bytes.
 *
 * \param info  The cipher info structure. This may be \c NULL.
 *
 * \return      The recommended IV size.
 * \return      \c 0 for ciphers not using an IV or a nonce.
 * \return      \c 0 if \p info is \c NULL.
 */
static inline size_t iotex_cipher_info_get_iv_size(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( 0 );

    return( (size_t) info->iv_size );
}

/**
 * \brief        This function returns the block size of the given
 *               cipher info structure in bytes.
 *
 * \param info   The cipher info structure. This may be \c NULL.
 *
 * \return       The block size of the cipher.
 * \return       \c 1 if the cipher is a stream cipher.
 * \return       \c 0 if \p info is \c NULL.
 */
static inline size_t iotex_cipher_info_get_block_size(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( 0 );

    return( (size_t) info->block_size );
}

/**
 * \brief        This function returns a non-zero value if the key length for
 *               the given cipher is variable.
 *
 * \param info   The cipher info structure. This may be \c NULL.
 *
 * \return       Non-zero if the key length is variable, \c 0 otherwise.
 * \return       \c 0 if the given pointer is \c NULL.
 */
static inline int iotex_cipher_info_has_variable_key_bitlen(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( 0 );

    return( info->flags & IOTEX_CIPHER_VARIABLE_KEY_LEN );
}

/**
 * \brief        This function returns a non-zero value if the IV size for
 *               the given cipher is variable.
 *
 * \param info   The cipher info structure. This may be \c NULL.
 *
 * \return       Non-zero if the IV size is variable, \c 0 otherwise.
 * \return       \c 0 if the given pointer is \c NULL.
 */
static inline int iotex_cipher_info_has_variable_iv_size(
    const iotex_cipher_info_t *info )
{
    if( info == NULL )
        return( 0 );

    return( info->flags & IOTEX_CIPHER_VARIABLE_IV_LEN );
}

/**
 * \brief               This function initializes a \p cipher_context as NONE.
 *
 * \param ctx           The context to be initialized. This must not be \c NULL.
 */
void iotex_cipher_init( iotex_cipher_context_t *ctx );

/**
 * \brief               This function frees and clears the cipher-specific
 *                      context of \p ctx. Freeing \p ctx itself remains the
 *                      responsibility of the caller.
 *
 * \param ctx           The context to be freed. If this is \c NULL, the
 *                      function has no effect, otherwise this must point to an
 *                      initialized context.
 */
void iotex_cipher_free( iotex_cipher_context_t *ctx );


/**
 * \brief               This function prepares a cipher context for
 *                      use with the given cipher primitive.
 *
 * \note                After calling this function, you should call
 *                      iotex_cipher_setkey() and, if the mode uses padding,
 *                      iotex_cipher_set_padding_mode(), then for each
 *                      message to encrypt or decrypt with this key, either:
 *                      - iotex_cipher_crypt() for one-shot processing with
 *                      non-AEAD modes;
 *                      - iotex_cipher_auth_encrypt_ext() or
 *                      iotex_cipher_auth_decrypt_ext() for one-shot
 *                      processing with AEAD modes or NIST_KW;
 *                      - for multi-part processing, see the documentation of
 *                      iotex_cipher_reset().
 *
 * \param ctx           The context to prepare. This must be initialized by
 *                      a call to iotex_cipher_init() first.
 * \param cipher_info   The cipher to use.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #IOTEX_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context fails.
 */
int iotex_cipher_setup( iotex_cipher_context_t *ctx,
                          const iotex_cipher_info_t *cipher_info );

#if defined(IOTEX_USE_PSA_CRYPTO)
#if !defined(IOTEX_DEPRECATED_REMOVED)
/**
 * \brief               This function initializes a cipher context for
 *                      PSA-based use with the given cipher primitive.
 *
 * \deprecated          This function is deprecated and will be removed in a
 *                      future version of the library.
 *                      Please use psa_aead_xxx() / psa_cipher_xxx() directly
 *                      instead.
 *
 * \note                See #IOTEX_USE_PSA_CRYPTO for information on PSA.
 *
 * \param ctx           The context to initialize. May not be \c NULL.
 * \param cipher_info   The cipher to use.
 * \param taglen        For AEAD ciphers, the length in bytes of the
 *                      authentication tag to use. Subsequent uses of
 *                      iotex_cipher_auth_encrypt_ext() or
 *                      iotex_cipher_auth_decrypt_ext() must provide
 *                      the same tag length.
 *                      For non-AEAD ciphers, the value must be \c 0.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #IOTEX_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context fails.
 */
int IOTEX_DEPRECATED iotex_cipher_setup_psa( iotex_cipher_context_t *ctx,
    const iotex_cipher_info_t *cipher_info, size_t taglen );
#endif /* IOTEX_DEPRECATED_REMOVED */
#endif /* IOTEX_USE_PSA_CRYPTO */

/**
 * \brief        This function returns the block size of the given cipher
 *               in bytes.
 *
 * \param ctx    The context of the cipher.
 *
 * \return       The block size of the underlying cipher.
 * \return       \c 1 if the cipher is a stream cipher.
 * \return       \c 0 if \p ctx has not been initialized.
 */
static inline unsigned int iotex_cipher_get_block_size(
    const iotex_cipher_context_t *ctx )
{
    IOTEX_INTERNAL_VALIDATE_RET( ctx != NULL, 0 );
    if( ctx->cipher_info == NULL )
        return 0;

    return ctx->cipher_info->block_size;
}

/**
 * \brief        This function returns the mode of operation for
 *               the cipher. For example, IOTEX_MODE_CBC.
 *
 * \param ctx    The context of the cipher. This must be initialized.
 *
 * \return       The mode of operation.
 * \return       #IOTEX_MODE_NONE if \p ctx has not been initialized.
 */
static inline iotex_cipher_mode_t iotex_cipher_get_cipher_mode(
    const iotex_cipher_context_t *ctx )
{
    IOTEX_INTERNAL_VALIDATE_RET( ctx != NULL, IOTEX_MODE_NONE );
    if( ctx->cipher_info == NULL )
        return IOTEX_MODE_NONE;

    return ctx->cipher_info->mode;
}

/**
 * \brief       This function returns the size of the IV or nonce
 *              of the cipher, in Bytes.
 *
 * \param ctx   The context of the cipher. This must be initialized.
 *
 * \return      The recommended IV size if no IV has been set.
 * \return      \c 0 for ciphers not using an IV or a nonce.
 * \return      The actual size if an IV has been set.
 */
static inline int iotex_cipher_get_iv_size(
    const iotex_cipher_context_t *ctx )
{
    IOTEX_INTERNAL_VALIDATE_RET( ctx != NULL, 0 );
    if( ctx->cipher_info == NULL )
        return 0;

    if( ctx->iv_size != 0 )
        return (int) ctx->iv_size;

    return (int) ctx->cipher_info->iv_size;
}

/**
 * \brief               This function returns the type of the given cipher.
 *
 * \param ctx           The context of the cipher. This must be initialized.
 *
 * \return              The type of the cipher.
 * \return              #IOTEX_CIPHER_NONE if \p ctx has not been initialized.
 */
static inline iotex_cipher_type_t iotex_cipher_get_type(
    const iotex_cipher_context_t *ctx )
{
    IOTEX_INTERNAL_VALIDATE_RET(
        ctx != NULL, IOTEX_CIPHER_NONE );
    if( ctx->cipher_info == NULL )
        return IOTEX_CIPHER_NONE;

    return ctx->cipher_info->type;
}

/**
 * \brief               This function returns the name of the given cipher
 *                      as a string.
 *
 * \param ctx           The context of the cipher. This must be initialized.
 *
 * \return              The name of the cipher.
 * \return              NULL if \p ctx has not been not initialized.
 */
static inline const char *iotex_cipher_get_name(
    const iotex_cipher_context_t *ctx )
{
    IOTEX_INTERNAL_VALIDATE_RET( ctx != NULL, 0 );
    if( ctx->cipher_info == NULL )
        return 0;

    return ctx->cipher_info->name;
}

/**
 * \brief               This function returns the key length of the cipher.
 *
 * \param ctx           The context of the cipher. This must be initialized.
 *
 * \return              The key length of the cipher in bits.
 * \return              #IOTEX_KEY_LENGTH_NONE if ctx \p has not been
 *                      initialized.
 */
static inline int iotex_cipher_get_key_bitlen(
    const iotex_cipher_context_t *ctx )
{
    IOTEX_INTERNAL_VALIDATE_RET(
        ctx != NULL, IOTEX_KEY_LENGTH_NONE );
    if( ctx->cipher_info == NULL )
        return IOTEX_KEY_LENGTH_NONE;

    return (int) ctx->cipher_info->key_bitlen;
}

/**
 * \brief          This function returns the operation of the given cipher.
 *
 * \param ctx      The context of the cipher. This must be initialized.
 *
 * \return         The type of operation: #IOTEX_ENCRYPT or #IOTEX_DECRYPT.
 * \return         #IOTEX_OPERATION_NONE if \p ctx has not been initialized.
 */
static inline iotex_operation_t iotex_cipher_get_operation(
    const iotex_cipher_context_t *ctx )
{
    IOTEX_INTERNAL_VALIDATE_RET(
        ctx != NULL, IOTEX_OPERATION_NONE );
    if( ctx->cipher_info == NULL )
        return IOTEX_OPERATION_NONE;

    return ctx->operation;
}

/**
 * \brief               This function sets the key to use with the given context.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a cipher information structure.
 * \param key           The key to use. This must be a readable buffer of at
 *                      least \p key_bitlen Bits.
 * \param key_bitlen    The key length to use, in Bits.
 * \param operation     The operation that the key will be used for:
 *                      #IOTEX_ENCRYPT or #IOTEX_DECRYPT.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              A cipher-specific error code on failure.
 */
int iotex_cipher_setkey( iotex_cipher_context_t *ctx,
                           const unsigned char *key,
                           int key_bitlen,
                           const iotex_operation_t operation );

#if defined(IOTEX_CIPHER_MODE_WITH_PADDING)
/**
 * \brief               This function sets the padding mode, for cipher modes
 *                      that use padding.
 *
 *                      The default passing mode is PKCS7 padding.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a cipher information structure.
 * \param mode          The padding mode.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE
 *                      if the selected padding mode is not supported.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA if the cipher mode
 *                      does not support padding.
 */
int iotex_cipher_set_padding_mode( iotex_cipher_context_t *ctx,
                                     iotex_cipher_padding_t mode );
#endif /* IOTEX_CIPHER_MODE_WITH_PADDING */

/**
 * \brief           This function sets the initialization vector (IV)
 *                  or nonce.
 *
 * \note            Some ciphers do not use IVs nor nonce. For these
 *                  ciphers, this function has no effect.
 *
 * \note            For #IOTEX_CIPHER_CHACHA20, the nonce length must
 *                  be 12, and the initial counter value is 0.
 *
 * \note            For #IOTEX_CIPHER_CHACHA20_POLY1305, the nonce length
 *                  must be 12.
 *
 * \param ctx       The generic cipher context. This must be initialized and
 *                  bound to a cipher information structure.
 * \param iv        The IV to use, or NONCE_COUNTER for CTR-mode ciphers. This
 *                  must be a readable buffer of at least \p iv_len Bytes.
 * \param iv_len    The IV length for ciphers with variable-size IV.
 *                  This parameter is discarded by ciphers with fixed-size IV.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                  parameter-verification failure.
 */
int iotex_cipher_set_iv( iotex_cipher_context_t *ctx,
                           const unsigned char *iv,
                           size_t iv_len );

/**
 * \brief         This function resets the cipher state.
 *
 * \note          With non-AEAD ciphers, the order of calls for each message
 *                is as follows:
 *                1. iotex_cipher_set_iv() if the mode uses an IV/nonce.
 *                2. iotex_cipher_reset()
 *                3. iotex_cipher_update() one or more times
 *                4. iotex_cipher_finish()
 *                .
 *                This sequence can be repeated to encrypt or decrypt multiple
 *                messages with the same key.
 *
 * \note          With AEAD ciphers, the order of calls for each message
 *                is as follows:
 *                1. iotex_cipher_set_iv() if the mode uses an IV/nonce.
 *                2. iotex_cipher_reset()
 *                3. iotex_cipher_update_ad()
 *                4. iotex_cipher_update() one or more times
 *                5. iotex_cipher_finish()
 *                6. iotex_cipher_check_tag() (for decryption) or
 *                iotex_cipher_write_tag() (for encryption).
 *                .
 *                This sequence can be repeated to encrypt or decrypt multiple
 *                messages with the same key.
 *
 * \param ctx     The generic cipher context. This must be bound to a key.
 *
 * \return        \c 0 on success.
 * \return        #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                parameter-verification failure.
 */
int iotex_cipher_reset( iotex_cipher_context_t *ctx );

#if defined(IOTEX_GCM_C) || defined(IOTEX_CHACHAPOLY_C)
/**
 * \brief               This function adds additional data for AEAD ciphers.
 *                      Currently supported with GCM and ChaCha20+Poly1305.
 *
 * \param ctx           The generic cipher context. This must be initialized.
 * \param ad            The additional data to use. This must be a readable
 *                      buffer of at least \p ad_len Bytes.
 * \param ad_len        The length of \p ad in Bytes.
 *
 * \return              \c 0 on success.
 * \return              A specific error code on failure.
 */
int iotex_cipher_update_ad( iotex_cipher_context_t *ctx,
                      const unsigned char *ad, size_t ad_len );
#endif /* IOTEX_GCM_C || IOTEX_CHACHAPOLY_C */

/**
 * \brief               The generic cipher update function. It encrypts or
 *                      decrypts using the given cipher context. Writes as
 *                      many block-sized blocks of data as possible to output.
 *                      Any data that cannot be written immediately is either
 *                      added to the next block, or flushed when
 *                      iotex_cipher_finish() is called.
 *                      Exception: For IOTEX_MODE_ECB, expects a single block
 *                      in size. For example, 16 Bytes for AES.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the output data. This must be able to
 *                      hold at least `ilen + block_size`. This must not be the
 *                      same buffer as \p input.
 * \param olen          The length of the output data, to be updated with the
 *                      actual number of Bytes written. This must not be
 *                      \c NULL.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE on an
 *                      unsupported mode for a cipher.
 * \return              A cipher-specific error code on failure.
 */
int iotex_cipher_update( iotex_cipher_context_t *ctx,
                           const unsigned char *input,
                           size_t ilen, unsigned char *output,
                           size_t *olen );

/**
 * \brief               The generic cipher finalization function. If data still
 *                      needs to be flushed from an incomplete block, the data
 *                      contained in it is padded to the size of
 *                      the last block, and written to the \p output buffer.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key.
 * \param output        The buffer to write data to. This needs to be a writable
 *                      buffer of at least \p block_size Bytes.
 * \param olen          The length of the data written to the \p output buffer.
 *                      This may not be \c NULL.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #IOTEX_ERR_CIPHER_FULL_BLOCK_EXPECTED on decryption
 *                      expecting a full block but not receiving one.
 * \return              #IOTEX_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting.
 * \return              A cipher-specific error code on failure.
 */
int iotex_cipher_finish( iotex_cipher_context_t *ctx,
                   unsigned char *output, size_t *olen );

#if defined(IOTEX_GCM_C) || defined(IOTEX_CHACHAPOLY_C)
/**
 * \brief               This function writes a tag for AEAD ciphers.
 *                      Currently supported with GCM and ChaCha20+Poly1305.
 *                      This must be called after iotex_cipher_finish().
 *
 * \param ctx           The generic cipher context. This must be initialized,
 *                      bound to a key, and have just completed a cipher
 *                      operation through iotex_cipher_finish() the tag for
 *                      which should be written.
 * \param tag           The buffer to write the tag to. This must be a writable
 *                      buffer of at least \p tag_len Bytes.
 * \param tag_len       The length of the tag to write.
 *
 * \return              \c 0 on success.
 * \return              A specific error code on failure.
 */
int iotex_cipher_write_tag( iotex_cipher_context_t *ctx,
                      unsigned char *tag, size_t tag_len );

/**
 * \brief               This function checks the tag for AEAD ciphers.
 *                      Currently supported with GCM and ChaCha20+Poly1305.
 *                      This must be called after iotex_cipher_finish().
 *
 * \param ctx           The generic cipher context. This must be initialized.
 * \param tag           The buffer holding the tag. This must be a readable
 *                      buffer of at least \p tag_len Bytes.
 * \param tag_len       The length of the tag to check.
 *
 * \return              \c 0 on success.
 * \return              A specific error code on failure.
 */
int iotex_cipher_check_tag( iotex_cipher_context_t *ctx,
                      const unsigned char *tag, size_t tag_len );
#endif /* IOTEX_GCM_C || IOTEX_CHACHAPOLY_C */

/**
 * \brief               The generic all-in-one encryption/decryption function,
 *                      for all ciphers except AEAD constructs.
 *
 * \param ctx           The generic cipher context. This must be initialized.
 * \param iv            The IV to use, or NONCE_COUNTER for CTR-mode ciphers.
 *                      This must be a readable buffer of at least \p iv_len
 *                      Bytes.
 * \param iv_len        The IV length for ciphers with variable-size IV.
 *                      This parameter is discarded by ciphers with fixed-size
 *                      IV.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes.
 * \param ilen          The length of the input data in Bytes.
 * \param output        The buffer for the output data. This must be able to
 *                      hold at least `ilen + block_size`. This must not be the
 *                      same buffer as \p input.
 * \param olen          The length of the output data, to be updated with the
 *                      actual number of Bytes written. This must not be
 *                      \c NULL.
 *
 * \note                Some ciphers do not use IVs nor nonce. For these
 *                      ciphers, use \p iv = NULL and \p iv_len = 0.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #IOTEX_ERR_CIPHER_FULL_BLOCK_EXPECTED on decryption
 *                      expecting a full block but not receiving one.
 * \return              #IOTEX_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting.
 * \return              A cipher-specific error code on failure.
 */
int iotex_cipher_crypt( iotex_cipher_context_t *ctx,
                  const unsigned char *iv, size_t iv_len,
                  const unsigned char *input, size_t ilen,
                  unsigned char *output, size_t *olen );

#if defined(IOTEX_CIPHER_MODE_AEAD) || defined(IOTEX_NIST_KW_C)
/**
 * \brief               The authenticated encryption (AEAD/NIST_KW) function.
 *
 * \note                For AEAD modes, the tag will be appended to the
 *                      ciphertext, as recommended by RFC 5116.
 *                      (NIST_KW doesn't have a separate tag.)
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key, with an AEAD algorithm or NIST_KW.
 * \param iv            The nonce to use. This must be a readable buffer of
 *                      at least \p iv_len Bytes and may be \c NULL if \p
 *                      iv_len is \c 0.
 * \param iv_len        The length of the nonce. For AEAD ciphers, this must
 *                      satisfy the constraints imposed by the cipher used.
 *                      For NIST_KW, this must be \c 0.
 * \param ad            The additional data to authenticate. This must be a
 *                      readable buffer of at least \p ad_len Bytes, and may
 *                      be \c NULL is \p ad_len is \c 0.
 * \param ad_len        The length of \p ad. For NIST_KW, this must be \c 0.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes, and may be
 *                      \c NULL if \p ilen is \c 0.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the output data. This must be a
 *                      writable buffer of at least \p output_len Bytes, and
 *                      must not be \c NULL.
 * \param output_len    The length of the \p output buffer in Bytes. For AEAD
 *                      ciphers, this must be at least \p ilen + \p tag_len.
 *                      For NIST_KW, this must be at least \p ilen + 8
 *                      (rounded up to a multiple of 8 if KWP is used);
 *                      \p ilen + 15 is always a safe value.
 * \param olen          This will be filled with the actual number of Bytes
 *                      written to the \p output buffer. This must point to a
 *                      writable object of type \c size_t.
 * \param tag_len       The desired length of the authentication tag. For AEAD
 *                      ciphers, this must match the constraints imposed by
 *                      the cipher used, and in particular must not be \c 0.
 *                      For NIST_KW, this must be \c 0.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              A cipher-specific error code on failure.
 */
int iotex_cipher_auth_encrypt_ext( iotex_cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *ad, size_t ad_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t output_len,
                         size_t *olen, size_t tag_len );

/**
 * \brief               The authenticated encryption (AEAD/NIST_KW) function.
 *
 * \note                If the data is not authentic, then the output buffer
 *                      is zeroed out to prevent the unauthentic plaintext being
 *                      used, making this interface safer.
 *
 * \note                For AEAD modes, the tag must be appended to the
 *                      ciphertext, as recommended by RFC 5116.
 *                      (NIST_KW doesn't have a separate tag.)
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key, with an AEAD algorithm or NIST_KW.
 * \param iv            The nonce to use. This must be a readable buffer of
 *                      at least \p iv_len Bytes and may be \c NULL if \p
 *                      iv_len is \c 0.
 * \param iv_len        The length of the nonce. For AEAD ciphers, this must
 *                      satisfy the constraints imposed by the cipher used.
 *                      For NIST_KW, this must be \c 0.
 * \param ad            The additional data to authenticate. This must be a
 *                      readable buffer of at least \p ad_len Bytes, and may
 *                      be \c NULL is \p ad_len is \c 0.
 * \param ad_len        The length of \p ad. For NIST_KW, this must be \c 0.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes, and may be
 *                      \c NULL if \p ilen is \c 0.
 * \param ilen          The length of the input data. For AEAD ciphers this
 *                      must be at least \p tag_len. For NIST_KW this must be
 *                      at least \c 8.
 * \param output        The buffer for the output data. This must be a
 *                      writable buffer of at least \p output_len Bytes, and
 *                      may be \c NULL if \p output_len is \c 0.
 * \param output_len    The length of the \p output buffer in Bytes. For AEAD
 *                      ciphers, this must be at least \p ilen - \p tag_len.
 *                      For NIST_KW, this must be at least \p ilen - 8.
 * \param olen          This will be filled with the actual number of Bytes
 *                      written to the \p output buffer. This must point to a
 *                      writable object of type \c size_t.
 * \param tag_len       The actual length of the authentication tag. For AEAD
 *                      ciphers, this must match the constraints imposed by
 *                      the cipher used, and in particular must not be \c 0.
 *                      For NIST_KW, this must be \c 0.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #IOTEX_ERR_CIPHER_AUTH_FAILED if data is not authentic.
 * \return              A cipher-specific error code on failure.
 */
int iotex_cipher_auth_decrypt_ext( iotex_cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *ad, size_t ad_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t output_len,
                         size_t *olen, size_t tag_len );
#endif /* IOTEX_CIPHER_MODE_AEAD || IOTEX_NIST_KW_C */
#ifdef __cplusplus
}
#endif

#endif /* IOTEX_CIPHER_H */
