#ifndef IOTEX_CHECK_CONFIG_H
#define IOTEX_CHECK_CONFIG_H

/*
 * We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */
#include <limits.h>
#if CHAR_BIT != 8
#error "mbed TLS requires a platform with 8-bit chars"
#endif

#if defined(_WIN32)
#if !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_C is required on Windows"
#endif

/* Fix the config here. Not convenient to put an #ifdef _WIN32 in iotex_config.h as
 * it would confuse config.py. */
#if !defined(IOTEX_PLATFORM_SNPRINTF_ALT) && \
    !defined(IOTEX_PLATFORM_SNPRINTF_MACRO)
#define IOTEX_PLATFORM_SNPRINTF_ALT
#endif

#if !defined(IOTEX_PLATFORM_VSNPRINTF_ALT) && \
    !defined(IOTEX_PLATFORM_VSNPRINTF_MACRO)
#define IOTEX_PLATFORM_VSNPRINTF_ALT
#endif
#endif /* _WIN32 */

#if defined(TARGET_LIKE_MBED) && defined(IOTEX_NET_C)
#error "The NET module is not available for mbed OS - please use the network functions provided by Mbed OS"
#endif

#if defined(IOTEX_DEPRECATED_WARNING) && \
    !defined(__GNUC__) && !defined(__clang__)
#error "IOTEX_DEPRECATED_WARNING only works with GCC and Clang"
#endif

#if defined(IOTEX_HAVE_TIME_DATE) && !defined(IOTEX_HAVE_TIME)
#error "IOTEX_HAVE_TIME_DATE without IOTEX_HAVE_TIME does not make sense"
#endif

#if defined(IOTEX_AESNI_C) && !defined(IOTEX_HAVE_ASM)
#error "IOTEX_AESNI_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_CTR_DRBG_C) && !defined(IOTEX_AES_C)
#error "IOTEX_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_DHM_C) && !defined(IOTEX_BIGNUM_C)
#error "IOTEX_DHM_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_CMAC_C) && \
    ( !defined(IOTEX_CIPHER_C ) || ( !defined(IOTEX_AES_C) && !defined(IOTEX_DES_C) ) )
#error "IOTEX_CMAC_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_NIST_KW_C) && \
    ( !defined(IOTEX_AES_C) || !defined(IOTEX_CIPHER_C) )
#error "IOTEX_NIST_KW_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECDH_C) && !defined(IOTEX_ECP_C)
#error "IOTEX_ECDH_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECDSA_C) &&            \
    ( !defined(IOTEX_ECP_C) ||           \
      !( defined(IOTEX_ECP_DP_SECP192R1_ENABLED) || \
         defined(IOTEX_ECP_DP_SECP224R1_ENABLED) || \
         defined(IOTEX_ECP_DP_SECP256R1_ENABLED) || \
         defined(IOTEX_ECP_DP_SECP384R1_ENABLED) || \
         defined(IOTEX_ECP_DP_SECP521R1_ENABLED) || \
         defined(IOTEX_ECP_DP_SECP192K1_ENABLED) || \
         defined(IOTEX_ECP_DP_SECP224K1_ENABLED) || \
         defined(IOTEX_ECP_DP_SECP256K1_ENABLED) || \
         defined(IOTEX_ECP_DP_BP256R1_ENABLED) ||   \
         defined(IOTEX_ECP_DP_BP384R1_ENABLED) ||   \
         defined(IOTEX_ECP_DP_BP512R1_ENABLED) ) || \
      !defined(IOTEX_ASN1_PARSE_C) ||    \
      !defined(IOTEX_ASN1_WRITE_C) )
#error "IOTEX_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECJPAKE_C) &&           \
    ( !defined(IOTEX_ECP_C) || !defined(IOTEX_MD_C) )
#error "IOTEX_ECJPAKE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_RESTARTABLE)           && \
    ( defined(IOTEX_USE_PSA_CRYPTO)          || \
      defined(IOTEX_ECDH_COMPUTE_SHARED_ALT) || \
      defined(IOTEX_ECDH_GEN_PUBLIC_ALT)     || \
      defined(IOTEX_ECDSA_SIGN_ALT)          || \
      defined(IOTEX_ECDSA_VERIFY_ALT)        || \
      defined(IOTEX_ECDSA_GENKEY_ALT)        || \
      defined(IOTEX_ECP_INTERNAL_ALT)        || \
      defined(IOTEX_ECP_ALT) )
#error "IOTEX_ECP_RESTARTABLE defined, but it cannot coexist with an alternative or PSA-based ECP implementation"
#endif

#if defined(IOTEX_ECDSA_DETERMINISTIC) && !defined(IOTEX_HMAC_DRBG_C)
#error "IOTEX_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_C) && ( !defined(IOTEX_BIGNUM_C) || (    \
    !defined(IOTEX_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(IOTEX_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(IOTEX_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(IOTEX_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_SECP256K1_ENABLED) &&                  \
    !defined(IOTEX_ECP_DP_CURVE25519_ENABLED) &&                 \
    !defined(IOTEX_ECP_DP_CURVE448_ENABLED) ) )
#error "IOTEX_ECP_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PK_PARSE_C) && !defined(IOTEX_ASN1_PARSE_C)
#error "IOTEX_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PKCS12_C) && !defined(IOTEX_CIPHER_C)
#error "IOTEX_PKCS12_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PKCS5_C) && (!defined(IOTEX_MD_C) || \
                                 !defined(IOTEX_CIPHER_C))
#error "IOTEX_PKCS5_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PKCS12_C) && !defined(IOTEX_MD_C)
#error "IOTEX_PKCS12_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PKCS1_V15) && !defined(IOTEX_MD_C)
#error "IOTEX_PKCS1_V15 defined, but not all prerequisites"
#endif

#if defined(IOTEX_PKCS1_V21) && !defined(IOTEX_MD_C)
#error "IOTEX_PKCS1_V21 defined, but not all prerequisites"
#endif

#if defined(IOTEX_ENTROPY_C) && (!defined(IOTEX_SHA512_C) &&      \
                                    !defined(IOTEX_SHA256_C))
#error "IOTEX_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(IOTEX_ENTROPY_C) && defined(IOTEX_SHA512_C) &&         \
    defined(IOTEX_CTR_DRBG_ENTROPY_LEN) && (IOTEX_CTR_DRBG_ENTROPY_LEN > 64)
#error "IOTEX_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(IOTEX_ENTROPY_C) &&                                            \
    ( !defined(IOTEX_SHA512_C) || defined(IOTEX_ENTROPY_FORCE_SHA256) ) \
    && defined(IOTEX_CTR_DRBG_ENTROPY_LEN) && (IOTEX_CTR_DRBG_ENTROPY_LEN > 32)
#error "IOTEX_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(IOTEX_ENTROPY_C) && \
    defined(IOTEX_ENTROPY_FORCE_SHA256) && !defined(IOTEX_SHA256_C)
#error "IOTEX_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define IOTEX_HAS_MEMSAN
#endif
#endif
#if defined(IOTEX_TEST_CONSTANT_FLOW_MEMSAN) &&  !defined(IOTEX_HAS_MEMSAN)
#error "IOTEX_TEST_CONSTANT_FLOW_MEMSAN requires building with MemorySanitizer"
#endif
#undef IOTEX_HAS_MEMSAN

#if defined(IOTEX_CCM_C) && (                                        \
    !defined(IOTEX_AES_C) && !defined(IOTEX_CAMELLIA_C) && !defined(IOTEX_ARIA_C) )
#error "IOTEX_CCM_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_CCM_C) && !defined(IOTEX_CIPHER_C)
#error "IOTEX_CCM_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_GCM_C) && (                                        \
    !defined(IOTEX_AES_C) && !defined(IOTEX_CAMELLIA_C) && !defined(IOTEX_ARIA_C) )
#error "IOTEX_GCM_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_GCM_C) && !defined(IOTEX_CIPHER_C)
#error "IOTEX_GCM_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_CHACHAPOLY_C) && !defined(IOTEX_CHACHA20_C)
#error "IOTEX_CHACHAPOLY_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_CHACHAPOLY_C) && !defined(IOTEX_POLY1305_C)
#error "IOTEX_CHACHAPOLY_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_RANDOMIZE_JAC_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_RANDOMIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_ADD_MIXED_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_ADD_MIXED_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_DOUBLE_JAC_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_DOUBLE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_NORMALIZE_JAC_MANY_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_NORMALIZE_JAC_MANY_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_NORMALIZE_JAC_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_NORMALIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_DOUBLE_ADD_MXZ_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_DOUBLE_ADD_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_RANDOMIZE_MXZ_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_RANDOMIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_NORMALIZE_MXZ_ALT) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_NORMALIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_ECP_NO_FALLBACK) && !defined(IOTEX_ECP_INTERNAL_ALT)
#error "IOTEX_ECP_NO_FALLBACK defined, but no alternative implementation enabled"
#endif

#if defined(IOTEX_HKDF_C) && !defined(IOTEX_MD_C)
#error "IOTEX_HKDF_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_HMAC_DRBG_C) && !defined(IOTEX_MD_C)
#error "IOTEX_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) &&                 \
    ( !defined(IOTEX_ECDH_C) || !defined(IOTEX_ECDSA_C) ||          \
      !defined(IOTEX_X509_CRT_PARSE_C) )
#error "IOTEX_KEY_EXCHANGE_ECDH_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_ECDH_RSA_ENABLED) &&                 \
    ( !defined(IOTEX_ECDH_C) || !defined(IOTEX_RSA_C) ||          \
      !defined(IOTEX_X509_CRT_PARSE_C) )
#error "IOTEX_KEY_EXCHANGE_ECDH_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(IOTEX_DHM_C)
#error "IOTEX_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(IOTEX_ECDH_C)
#error "IOTEX_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(IOTEX_DHM_C) || !defined(IOTEX_RSA_C) ||           \
      !defined(IOTEX_X509_CRT_PARSE_C) || !defined(IOTEX_PKCS1_V15) )
#error "IOTEX_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(IOTEX_ECDH_C) || !defined(IOTEX_RSA_C) ||          \
      !defined(IOTEX_X509_CRT_PARSE_C) || !defined(IOTEX_PKCS1_V15) )
#error "IOTEX_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(IOTEX_ECDH_C) || !defined(IOTEX_ECDSA_C) ||          \
      !defined(IOTEX_X509_CRT_PARSE_C) )
#error "IOTEX_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(IOTEX_RSA_C) || !defined(IOTEX_X509_CRT_PARSE_C) || \
      !defined(IOTEX_PKCS1_V15) )
#error "IOTEX_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(IOTEX_RSA_C) || !defined(IOTEX_X509_CRT_PARSE_C) || \
      !defined(IOTEX_PKCS1_V15) )
#error "IOTEX_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_ECJPAKE_ENABLED) &&                    \
    ( !defined(IOTEX_ECJPAKE_C) || !defined(IOTEX_SHA256_C) ||      \
      !defined(IOTEX_ECP_DP_SECP256R1_ENABLED) )
#error "IOTEX_KEY_EXCHANGE_ECJPAKE_ENABLED defined, but not all prerequisites"
#endif

#if defined(IOTEX_KEY_EXCHANGE_WITH_CERT_ENABLED) &&        \
    !defined(IOTEX_SSL_KEEP_PEER_CERTIFICATE) &&              \
    ( !defined(IOTEX_SHA256_C) &&                             \
      !defined(IOTEX_SHA512_C) &&                             \
      !defined(IOTEX_SHA1_C) )
#error "!IOTEX_SSL_KEEP_PEER_CERTIFICATE requires IOTEX_SHA512_C, IOTEX_SHA256_C or IOTEX_SHA1_C"
#endif

#if defined(IOTEX_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(IOTEX_PLATFORM_C) || !defined(IOTEX_PLATFORM_MEMORY) )
#error "IOTEX_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_MEMORY_BACKTRACE) && !defined(IOTEX_MEMORY_BUFFER_ALLOC_C)
#error "IOTEX_MEMORY_BACKTRACE defined, but not all prerequisites"
#endif

#if defined(IOTEX_MEMORY_DEBUG) && !defined(IOTEX_MEMORY_BUFFER_ALLOC_C)
#error "IOTEX_MEMORY_DEBUG defined, but not all prerequisites"
#endif

#if defined(IOTEX_PADLOCK_C) && !defined(IOTEX_HAVE_ASM)
#error "IOTEX_PADLOCK_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PEM_PARSE_C) && !defined(IOTEX_BASE64_C)
#error "IOTEX_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PEM_WRITE_C) && !defined(IOTEX_BASE64_C)
#error "IOTEX_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PK_C) && \
    ( !defined(IOTEX_MD_C) || ( !defined(IOTEX_RSA_C) && !defined(IOTEX_ECP_C) ) )
#error "IOTEX_PK_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PK_PARSE_C) && !defined(IOTEX_PK_C)
#error "IOTEX_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PK_WRITE_C) && !defined(IOTEX_PK_C)
#error "IOTEX_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_EXIT_ALT) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_EXIT_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_EXIT_MACRO) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_EXIT_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_EXIT_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_EXIT) ||\
        defined(IOTEX_PLATFORM_EXIT_ALT) )
#error "IOTEX_PLATFORM_EXIT_MACRO and IOTEX_PLATFORM_STD_EXIT/IOTEX_PLATFORM_EXIT_ALT cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_SETBUF_ALT) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_SETBUF_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_SETBUF_MACRO) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_SETBUF_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_SETBUF_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_SETBUF) ||\
        defined(IOTEX_PLATFORM_SETBUF_ALT) )
#error "IOTEX_PLATFORM_SETBUF_MACRO and IOTEX_PLATFORM_STD_SETBUF/IOTEX_PLATFORM_SETBUF_ALT cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_TIME_ALT) &&\
    ( !defined(IOTEX_PLATFORM_C) ||\
        !defined(IOTEX_HAVE_TIME) )
#error "IOTEX_PLATFORM_TIME_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_TIME_MACRO) &&\
    ( !defined(IOTEX_PLATFORM_C) ||\
        !defined(IOTEX_HAVE_TIME) )
#error "IOTEX_PLATFORM_TIME_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_TIME_TYPE_MACRO) &&\
    ( !defined(IOTEX_PLATFORM_C) ||\
        !defined(IOTEX_HAVE_TIME) )
#error "IOTEX_PLATFORM_TIME_TYPE_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_TIME_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_TIME) ||\
        defined(IOTEX_PLATFORM_TIME_ALT) )
#error "IOTEX_PLATFORM_TIME_MACRO and IOTEX_PLATFORM_STD_TIME/IOTEX_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_TIME_TYPE_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_TIME) ||\
        defined(IOTEX_PLATFORM_TIME_ALT) )
#error "IOTEX_PLATFORM_TIME_TYPE_MACRO and IOTEX_PLATFORM_STD_TIME/IOTEX_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_FPRINTF_ALT) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_FPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_FPRINTF_MACRO) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_FPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_FPRINTF_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_FPRINTF) ||\
        defined(IOTEX_PLATFORM_FPRINTF_ALT) )
#error "IOTEX_PLATFORM_FPRINTF_MACRO and IOTEX_PLATFORM_STD_FPRINTF/IOTEX_PLATFORM_FPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_FREE_MACRO) &&\
    ( !defined(IOTEX_PLATFORM_C) || !defined(IOTEX_PLATFORM_MEMORY) )
#error "IOTEX_PLATFORM_FREE_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_FREE_MACRO) &&\
    defined(IOTEX_PLATFORM_STD_FREE)
#error "IOTEX_PLATFORM_FREE_MACRO and IOTEX_PLATFORM_STD_FREE cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_FREE_MACRO) && !defined(IOTEX_PLATFORM_CALLOC_MACRO)
#error "IOTEX_PLATFORM_CALLOC_MACRO must be defined if IOTEX_PLATFORM_FREE_MACRO is"
#endif

#if defined(IOTEX_PLATFORM_CALLOC_MACRO) &&\
    ( !defined(IOTEX_PLATFORM_C) || !defined(IOTEX_PLATFORM_MEMORY) )
#error "IOTEX_PLATFORM_CALLOC_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_CALLOC_MACRO) &&\
    defined(IOTEX_PLATFORM_STD_CALLOC)
#error "IOTEX_PLATFORM_CALLOC_MACRO and IOTEX_PLATFORM_STD_CALLOC cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_CALLOC_MACRO) && !defined(IOTEX_PLATFORM_FREE_MACRO)
#error "IOTEX_PLATFORM_FREE_MACRO must be defined if IOTEX_PLATFORM_CALLOC_MACRO is"
#endif

#if defined(IOTEX_PLATFORM_MEMORY) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_MEMORY defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_PRINTF_ALT) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_PRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_PRINTF_MACRO) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_PRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_PRINTF_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_PRINTF) ||\
        defined(IOTEX_PLATFORM_PRINTF_ALT) )
#error "IOTEX_PLATFORM_PRINTF_MACRO and IOTEX_PLATFORM_STD_PRINTF/IOTEX_PLATFORM_PRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_SNPRINTF_ALT) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_SNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_SNPRINTF_MACRO) && !defined(IOTEX_PLATFORM_C)
#error "IOTEX_PLATFORM_SNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_SNPRINTF_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_SNPRINTF) ||\
        defined(IOTEX_PLATFORM_SNPRINTF_ALT) )
#error "IOTEX_PLATFORM_SNPRINTF_MACRO and IOTEX_PLATFORM_STD_SNPRINTF/IOTEX_PLATFORM_SNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_STD_MEM_HDR) &&\
    !defined(IOTEX_PLATFORM_NO_STD_FUNCTIONS)
#error "IOTEX_PLATFORM_STD_MEM_HDR defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_CALLOC) && !defined(IOTEX_PLATFORM_MEMORY)
#error "IOTEX_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_FREE) && !defined(IOTEX_PLATFORM_MEMORY)
#error "IOTEX_PLATFORM_STD_FREE defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_EXIT) &&\
    !defined(IOTEX_PLATFORM_EXIT_ALT)
#error "IOTEX_PLATFORM_STD_EXIT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_TIME) &&\
    ( !defined(IOTEX_PLATFORM_TIME_ALT) ||\
        !defined(IOTEX_HAVE_TIME) )
#error "IOTEX_PLATFORM_STD_TIME defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_FPRINTF) &&\
    !defined(IOTEX_PLATFORM_FPRINTF_ALT)
#error "IOTEX_PLATFORM_STD_FPRINTF defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_PRINTF) &&\
    !defined(IOTEX_PLATFORM_PRINTF_ALT)
#error "IOTEX_PLATFORM_STD_PRINTF defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_SNPRINTF) &&\
    !defined(IOTEX_PLATFORM_SNPRINTF_ALT)
#error "IOTEX_PLATFORM_STD_SNPRINTF defined, but not all prerequisites"
#endif

#if defined(IOTEX_ENTROPY_NV_SEED) &&\
    ( !defined(IOTEX_PLATFORM_C) || !defined(IOTEX_ENTROPY_C) )
#error "IOTEX_ENTROPY_NV_SEED defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_NV_SEED_ALT) &&\
    !defined(IOTEX_ENTROPY_NV_SEED)
#error "IOTEX_PLATFORM_NV_SEED_ALT defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_NV_SEED_READ) &&\
    !defined(IOTEX_PLATFORM_NV_SEED_ALT)
#error "IOTEX_PLATFORM_STD_NV_SEED_READ defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_STD_NV_SEED_WRITE) &&\
    !defined(IOTEX_PLATFORM_NV_SEED_ALT)
#error "IOTEX_PLATFORM_STD_NV_SEED_WRITE defined, but not all prerequisites"
#endif

#if defined(IOTEX_PLATFORM_NV_SEED_READ_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_NV_SEED_READ) ||\
      defined(IOTEX_PLATFORM_NV_SEED_ALT) )
#error "IOTEX_PLATFORM_NV_SEED_READ_MACRO and IOTEX_PLATFORM_STD_NV_SEED_READ cannot be defined simultaneously"
#endif

#if defined(IOTEX_PLATFORM_NV_SEED_WRITE_MACRO) &&\
    ( defined(IOTEX_PLATFORM_STD_NV_SEED_WRITE) ||\
      defined(IOTEX_PLATFORM_NV_SEED_ALT) )
#error "IOTEX_PLATFORM_NV_SEED_WRITE_MACRO and IOTEX_PLATFORM_STD_NV_SEED_WRITE cannot be defined simultaneously"
#endif

#if defined(IOTEX_PSA_CRYPTO_C) &&                                    \
    !( ( ( defined(IOTEX_CTR_DRBG_C) || defined(IOTEX_HMAC_DRBG_C) ) && \
         defined(IOTEX_ENTROPY_C) ) ||                                \
       defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG) )
#error "IOTEX_PSA_CRYPTO_C defined, but not all prerequisites (missing RNG)"
#endif

#if defined(IOTEX_PSA_CRYPTO_C) && !defined(IOTEX_CIPHER_C )
#error "IOTEX_PSA_CRYPTO_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PSA_CRYPTO_SPM) && !defined(IOTEX_PSA_CRYPTO_C)
#error "IOTEX_PSA_CRYPTO_SPM defined, but not all prerequisites"
#endif

#if defined(IOTEX_PSA_CRYPTO_SE_C) &&    \
    ! ( defined(IOTEX_PSA_CRYPTO_C) && \
        defined(IOTEX_PSA_CRYPTO_STORAGE_C) )
#error "IOTEX_PSA_CRYPTO_SE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PSA_CRYPTO_SE_C)
#if defined(IOTEX_DEPRECATED_REMOVED)
#error "IOTEX_PSA_CRYPTO_SE_C is deprecated and will be removed in a future version of Mbed TLS"
#elif defined(IOTEX_DEPRECATED_WARNING)
#warning "IOTEX_PSA_CRYPTO_SE_C is deprecated and will be removed in a future version of Mbed TLS"
#endif
#endif /* IOTEX_PSA_CRYPTO_SE_C */

#if defined(IOTEX_PSA_CRYPTO_STORAGE_C) &&            \
    ! defined(IOTEX_PSA_CRYPTO_C)
#error "IOTEX_PSA_CRYPTO_STORAGE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PSA_INJECT_ENTROPY) &&      \
    !( defined(IOTEX_PSA_CRYPTO_STORAGE_C) && \
       defined(IOTEX_ENTROPY_NV_SEED) )
#error "IOTEX_PSA_INJECT_ENTROPY defined, but not all prerequisites"
#endif

#if defined(IOTEX_PSA_INJECT_ENTROPY) &&              \
    !defined(IOTEX_NO_DEFAULT_ENTROPY_SOURCES)
#error "IOTEX_PSA_INJECT_ENTROPY is not compatible with actual entropy sources"
#endif

#if defined(IOTEX_PSA_INJECT_ENTROPY) &&              \
    defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG)
#error "IOTEX_PSA_INJECT_ENTROPY is not compatible with IOTEX_PSA_CRYPTO_EXTERNAL_RNG"
#endif

#if defined(IOTEX_PSA_ITS_FILE_C) && \
    !defined(IOTEX_FS_IO)
#error "IOTEX_PSA_ITS_FILE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_PSA_ITS_FILE_C) && \
    defined(IOTEX_PSA_ITS_FLASH_C)
#error "IOTEX_PSA_ITS_FILE_C is not compatible with IOTEX_PSA_ITS_FLASH_C"
#endif

#if defined(IOTEX_RSA_C) && ( !defined(IOTEX_BIGNUM_C) ||         \
    !defined(IOTEX_OID_C) )
#error "IOTEX_RSA_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_RSA_C) && ( !defined(IOTEX_PKCS1_V21) &&         \
    !defined(IOTEX_PKCS1_V15) )
#error "IOTEX_RSA_C defined, but none of the PKCS1 versions enabled"
#endif

#if defined(IOTEX_X509_RSASSA_PSS_SUPPORT) &&                        \
    ( !defined(IOTEX_RSA_C) || !defined(IOTEX_PKCS1_V21) )
#error "IOTEX_X509_RSASSA_PSS_SUPPORT defined, but not all prerequisites"
#endif

#if defined(IOTEX_SHA384_C) && !defined(IOTEX_SHA512_C)
#error "IOTEX_SHA384_C defined without IOTEX_SHA512_C"
#endif

#if defined(IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT) && \
    defined(IOTEX_SHA512_USE_A64_CRYPTO_ONLY)
#error "Must only define one of IOTEX_SHA512_USE_A64_CRYPTO_*"
#endif

#if defined(IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT) || \
    defined(IOTEX_SHA512_USE_A64_CRYPTO_ONLY)
#if !defined(IOTEX_SHA512_C)
#error "IOTEX_SHA512_USE_A64_CRYPTO_* defined without IOTEX_SHA512_C"
#endif
#if defined(IOTEX_SHA512_ALT) || defined(IOTEX_SHA512_PROCESS_ALT)
#error "IOTEX_SHA512_*ALT can't be used with IOTEX_SHA512_USE_A64_CRYPTO_*"
#endif
/*
 * Best performance comes from most recent compilers, with intrinsics and -O3.
 * Must compile with -march=armv8.2-a+sha3, but we can't detect armv8.2-a, and
 * can't always detect __ARM_FEATURE_SHA512 (notably clang 7-12).
 *
 * GCC < 8 won't work at all (lacks the sha512 instructions)
 * GCC >= 8 uses intrinsics, sets __ARM_FEATURE_SHA512
 *
 * Clang < 7 won't work at all (lacks the sha512 instructions)
 * Clang 7-12 don't have intrinsics (but we work around that with inline
 *            assembler) or __ARM_FEATURE_SHA512
 * Clang == 13.0.0 same as clang 12 (only seen on macOS)
 * Clang >= 13.0.1 has __ARM_FEATURE_SHA512 and intrinsics
 */
#if defined(__aarch64__) && !defined(__ARM_FEATURE_SHA512)
   /* Test Clang first, as it defines __GNUC__ */
#  if defined(__clang__)
#    if __clang_major__ < 7
#      error "A more recent Clang is required for IOTEX_SHA512_USE_A64_CRYPTO_*"
#    elif __clang_major__ < 13 || \
         (__clang_major__ == 13 && __clang_minor__ == 0 && __clang_patchlevel__ == 0)
       /* We implement the intrinsics with inline assembler, so don't error */
#    else
#      error "Must use minimum -march=armv8.2-a+sha3 for IOTEX_SHA512_USE_A64_CRYPTO_*"
#    endif
#  elif defined(__GNUC__)
#    if __GNUC__ < 8
#      error "A more recent GCC is required for IOTEX_SHA512_USE_A64_CRYPTO_*"
#    else
#      error "Must use minimum -march=armv8.2-a+sha3 for IOTEX_SHA512_USE_A64_CRYPTO_*"
#    endif
#  else
#    error "Only GCC and Clang supported for IOTEX_SHA512_USE_A64_CRYPTO_*"
#  endif
#endif

#endif /* IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT || IOTEX_SHA512_USE_A64_CRYPTO_ONLY */

#if defined(IOTEX_SHA512_USE_A64_CRYPTO_ONLY) && !defined(__aarch64__)
#error "IOTEX_SHA512_USE_A64_CRYPTO_ONLY defined on non-Aarch64 system"
#endif

#if defined(IOTEX_SHA224_C) && !defined(IOTEX_SHA256_C)
#error "IOTEX_SHA224_C defined without IOTEX_SHA256_C"
#endif

#if defined(IOTEX_SHA256_C) && !defined(IOTEX_SHA224_C)
#error "IOTEX_SHA256_C defined without IOTEX_SHA224_C"
#endif

#if defined(IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT) && \
    defined(IOTEX_SHA256_USE_A64_CRYPTO_ONLY)
#error "Must only define one of IOTEX_SHA256_USE_A64_CRYPTO_*"
#endif

#if defined(IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT) || \
    defined(IOTEX_SHA256_USE_A64_CRYPTO_ONLY)
#if !defined(IOTEX_SHA256_C)
#error "IOTEX_SHA256_USE_A64_CRYPTO_* defined without IOTEX_SHA256_C"
#endif
#if defined(IOTEX_SHA256_ALT) || defined(IOTEX_SHA256_PROCESS_ALT)
#error "IOTEX_SHA256_*ALT can't be used with IOTEX_SHA256_USE_A64_CRYPTO_*"
#endif
#if defined(__aarch64__) && !defined(__ARM_FEATURE_CRYPTO)
#error "Must use minimum -march=armv8-a+crypto for IOTEX_SHA256_USE_A64_CRYPTO_*"
#endif
#endif

#if defined(IOTEX_SHA256_USE_A64_CRYPTO_ONLY) && \
    !defined(__aarch64__) && !defined(_M_ARM64)
#error "IOTEX_SHA256_USE_A64_CRYPTO_ONLY defined on non-Aarch64 system"
#endif

#if defined(IOTEX_SSL_PROTO_TLS1_2) && ( !defined(IOTEX_SHA1_C) &&     \
    !defined(IOTEX_SHA256_C) && !defined(IOTEX_SHA512_C) )
#error "IOTEX_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

/*
 * HKDF is mandatory for TLS 1.3.
 * Otherwise support for at least one ciphersuite mandates either SHA_256 or
 * SHA_384.
 */
#if defined(IOTEX_SSL_PROTO_TLS1_3) && \
    ( ( !defined(IOTEX_HKDF_C) ) || \
      ( !defined(IOTEX_SHA256_C) && !defined(IOTEX_SHA384_C) ) || \
      ( !defined(IOTEX_PSA_CRYPTO_C) ) )
#error "IOTEX_SSL_PROTO_TLS1_3 defined, but not all prerequisites"
#endif

/*
 * The current implementation of TLS 1.3 requires IOTEX_SSL_KEEP_PEER_CERTIFICATE.
 */
#if defined(IOTEX_SSL_PROTO_TLS1_3) && !defined(IOTEX_SSL_KEEP_PEER_CERTIFICATE)
#error "IOTEX_SSL_PROTO_TLS1_3 defined without IOTEX_SSL_KEEP_PEER_CERTIFICATE"
#endif

#if defined(IOTEX_SSL_PROTO_TLS1_2) &&                                    \
    !(defined(IOTEX_KEY_EXCHANGE_RSA_ENABLED) ||                          \
      defined(IOTEX_KEY_EXCHANGE_DHE_RSA_ENABLED) ||                      \
      defined(IOTEX_KEY_EXCHANGE_ECDHE_RSA_ENABLED) ||                    \
      defined(IOTEX_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) ||                  \
      defined(IOTEX_KEY_EXCHANGE_ECDH_RSA_ENABLED) ||                     \
      defined(IOTEX_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) ||                   \
      defined(IOTEX_KEY_EXCHANGE_PSK_ENABLED) ||                          \
      defined(IOTEX_KEY_EXCHANGE_DHE_PSK_ENABLED) ||                      \
      defined(IOTEX_KEY_EXCHANGE_RSA_PSK_ENABLED) ||                      \
      defined(IOTEX_KEY_EXCHANGE_ECDHE_PSK_ENABLED) ||                    \
      defined(IOTEX_KEY_EXCHANGE_ECJPAKE_ENABLED) )
#error "One or more versions of the TLS protocol are enabled " \
        "but no key exchange methods defined with IOTEX_KEY_EXCHANGE_xxxx"
#endif

#if defined(IOTEX_SSL_PROTO_DTLS)     && \
    !defined(IOTEX_SSL_PROTO_TLS1_2)
#error "IOTEX_SSL_PROTO_DTLS defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_CLI_C) && !defined(IOTEX_SSL_TLS_C)
#error "IOTEX_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_TLS_C) && ( !defined(IOTEX_CIPHER_C) ||     \
    !defined(IOTEX_MD_C) )
#error "IOTEX_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_SRV_C) && !defined(IOTEX_SSL_TLS_C)
#error "IOTEX_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_TLS_C) && \
    !( defined(IOTEX_SSL_PROTO_TLS1_2) || defined(IOTEX_SSL_PROTO_TLS1_3) )
#error "IOTEX_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(IOTEX_SSL_DTLS_HELLO_VERIFY) && !defined(IOTEX_SSL_PROTO_DTLS)
#error "IOTEX_SSL_DTLS_HELLO_VERIFY  defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_DTLS_CLIENT_PORT_REUSE) && \
    !defined(IOTEX_SSL_DTLS_HELLO_VERIFY)
#error "IOTEX_SSL_DTLS_CLIENT_PORT_REUSE  defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_DTLS_ANTI_REPLAY) &&                              \
    ( !defined(IOTEX_SSL_TLS_C) || !defined(IOTEX_SSL_PROTO_DTLS) )
#error "IOTEX_SSL_DTLS_ANTI_REPLAY  defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_DTLS_CONNECTION_ID) &&                              \
    ( !defined(IOTEX_SSL_TLS_C) || !defined(IOTEX_SSL_PROTO_DTLS) )
#error "IOTEX_SSL_DTLS_CONNECTION_ID  defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_DTLS_CONNECTION_ID)            &&                 \
    defined(IOTEX_SSL_CID_IN_LEN_MAX) &&                 \
    IOTEX_SSL_CID_IN_LEN_MAX > 255
#error "IOTEX_SSL_CID_IN_LEN_MAX too large (max 255)"
#endif

#if defined(IOTEX_SSL_DTLS_CONNECTION_ID)            &&                  \
    defined(IOTEX_SSL_CID_OUT_LEN_MAX) &&                 \
    IOTEX_SSL_CID_OUT_LEN_MAX > 255
#error "IOTEX_SSL_CID_OUT_LEN_MAX too large (max 255)"
#endif

#if defined(IOTEX_SSL_ENCRYPT_THEN_MAC) &&   \
    !defined(IOTEX_SSL_PROTO_TLS1_2)
#error "IOTEX_SSL_ENCRYPT_THEN_MAC defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_EXTENDED_MASTER_SECRET) && \
    !defined(IOTEX_SSL_PROTO_TLS1_2)
#error "IOTEX_SSL_EXTENDED_MASTER_SECRET defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_TICKET_C) && ( !defined(IOTEX_CIPHER_C) && \
                                       !defined(IOTEX_USE_PSA_CRYPTO) )
#error "IOTEX_SSL_TICKET_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_SERVER_NAME_INDICATION) && \
        !defined(IOTEX_X509_CRT_PARSE_C)
#error "IOTEX_SSL_SERVER_NAME_INDICATION defined, but not all prerequisites"
#endif

#if defined(IOTEX_THREADING_PTHREAD)
#if !defined(IOTEX_THREADING_C) || defined(IOTEX_THREADING_IMPL)
#error "IOTEX_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define IOTEX_THREADING_IMPL
#endif

#if defined(IOTEX_THREADING_ALT)
#if !defined(IOTEX_THREADING_C) || defined(IOTEX_THREADING_IMPL)
#error "IOTEX_THREADING_ALT defined, but not all prerequisites"
#endif
#define IOTEX_THREADING_IMPL
#endif

#if defined(IOTEX_THREADING_C) && !defined(IOTEX_THREADING_IMPL)
#error "IOTEX_THREADING_C defined, single threading implementation required"
#endif
#undef IOTEX_THREADING_IMPL

#if defined(IOTEX_USE_PSA_CRYPTO) && !defined(IOTEX_PSA_CRYPTO_C)
#error "IOTEX_USE_PSA_CRYPTO defined, but not all prerequisites"
#endif

#if defined(IOTEX_VERSION_FEATURES) && !defined(IOTEX_VERSION_C)
#error "IOTEX_VERSION_FEATURES defined, but not all prerequisites"
#endif

#if defined(IOTEX_X509_USE_C) && ( !defined(IOTEX_BIGNUM_C) ||  \
    !defined(IOTEX_OID_C) || !defined(IOTEX_ASN1_PARSE_C) ||      \
    !defined(IOTEX_PK_PARSE_C) )
#error "IOTEX_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_X509_CREATE_C) && ( !defined(IOTEX_BIGNUM_C) ||  \
    !defined(IOTEX_OID_C) || !defined(IOTEX_ASN1_WRITE_C) ||       \
    !defined(IOTEX_PK_WRITE_C) )
#error "IOTEX_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_X509_CRT_PARSE_C) && ( !defined(IOTEX_X509_USE_C) )
#error "IOTEX_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_X509_CRL_PARSE_C) && ( !defined(IOTEX_X509_USE_C) )
#error "IOTEX_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_X509_CSR_PARSE_C) && ( !defined(IOTEX_X509_USE_C) )
#error "IOTEX_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_X509_CRT_WRITE_C) && ( !defined(IOTEX_X509_CREATE_C) )
#error "IOTEX_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_X509_CSR_WRITE_C) && ( !defined(IOTEX_X509_CREATE_C) )
#error "IOTEX_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#if defined(IOTEX_HAVE_INT32) && defined(IOTEX_HAVE_INT64)
#error "IOTEX_HAVE_INT32 and IOTEX_HAVE_INT64 cannot be defined simultaneously"
#endif /* IOTEX_HAVE_INT32 && IOTEX_HAVE_INT64 */

#if ( defined(IOTEX_HAVE_INT32) || defined(IOTEX_HAVE_INT64) ) && \
    defined(IOTEX_HAVE_ASM)
#error "IOTEX_HAVE_INT32/IOTEX_HAVE_INT64 and IOTEX_HAVE_ASM cannot be defined simultaneously"
#endif /* (IOTEX_HAVE_INT32 || IOTEX_HAVE_INT64) && IOTEX_HAVE_ASM */

#if defined(IOTEX_SSL_DTLS_SRTP) && ( !defined(IOTEX_SSL_PROTO_DTLS) )
#error "IOTEX_SSL_DTLS_SRTP defined, but not all prerequisites"
#endif

#if defined(IOTEX_SSL_VARIABLE_BUFFER_LENGTH) && ( !defined(IOTEX_SSL_MAX_FRAGMENT_LENGTH) )
#error "IOTEX_SSL_VARIABLE_BUFFER_LENGTH defined, but not all prerequisites"
#endif



/* Reject attempts to enable options that have been removed and that could
 * cause a build to succeed but with features removed. */

#if defined(IOTEX_HAVEGE_C) //no-check-names
#error "IOTEX_HAVEGE_C was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/2599"
#endif

#if defined(IOTEX_SSL_HW_RECORD_ACCEL) //no-check-names
#error "IOTEX_SSL_HW_RECORD_ACCEL was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4031"
#endif

#if defined(IOTEX_SSL_PROTO_SSL3) //no-check-names
#error "IOTEX_SSL_PROTO_SSL3 (SSL v3.0 support) was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4031"
#endif

#if defined(IOTEX_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO) //no-check-names
#error "IOTEX_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO (SSL v2 ClientHello support) was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4031"
#endif

#if defined(IOTEX_SSL_TRUNCATED_HMAC_COMPAT) //no-check-names
#error "IOTEX_SSL_TRUNCATED_HMAC_COMPAT (compatibility with the buggy implementation of truncated HMAC in Mbed TLS up to 2.7) was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4031"
#endif

#if defined(IOTEX_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES) //no-check-names
#error "IOTEX_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES was removed in Mbed TLS 3.0. See the ChangeLog entry if you really need SHA-1-signed certificates."
#endif

#if defined(IOTEX_ZLIB_SUPPORT) //no-check-names
#error "IOTEX_ZLIB_SUPPORT was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4031"
#endif

#if defined(IOTEX_CHECK_PARAMS) //no-check-names
#error "IOTEX_CHECK_PARAMS was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4313"
#endif

#if defined(IOTEX_SSL_CID_PADDING_GRANULARITY) //no-check-names
#error "IOTEX_SSL_CID_PADDING_GRANULARITY was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4335"
#endif

#if defined(IOTEX_SSL_TLS1_3_PADDING_GRANULARITY) //no-check-names
#error "IOTEX_SSL_TLS1_3_PADDING_GRANULARITY was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4335"
#endif

#if defined(IOTEX_SSL_TRUNCATED_HMAC) //no-check-names
#error "IOTEX_SSL_TRUNCATED_HMAC was removed in Mbed TLS 3.0. See https://github.com/Mbed-TLS/mbedtls/issues/4341"
#endif

/*
 * Avoid warning from -pedantic. This is a convenient place for this
 * workaround since this is included by every single file before the
 * #if defined(IOTEX_xxx_C) that results in empty translation units.
 */
typedef int iotex_iso_c_forbids_empty_translation_units;

#endif /* IOTEX_CHECK_CONFIG_H */
