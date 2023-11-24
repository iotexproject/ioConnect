#include <string.h>
#include "include/common.h"
#include "include/iotex/platform.h"

#if defined(IOTEX_PSA_CRYPTO_C)
#if defined(IOTEX_PSA_CRYPTO_ACCELERATION_ENABLE) && defined(IOTEX_CRYPTO_RSA_ACCELETATION_SUPPORT)
#include <server/crypto/psa_crypto_core.h>
#include <server/crypto/psa_crypto_rsa.h>
#if defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)
#include "include/mbedtls/rsa.h"
#endif

psa_status_t iotex_crypto_acceleration_asymmetric_encrypt( const psa_key_attributes_t *attributes,
                                             const uint8_t *key_buffer,
                                             size_t key_buffer_size,
                                             psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             const uint8_t *salt,
                                             size_t salt_length,
                                             uint8_t *output,
                                             size_t output_size,
                                             size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	// TODO:
	status = iotex_acc_lib_psa_hash_compute( operation, alg );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

    if( PSA_KEY_TYPE_IS_RSA( attributes->core.type ) )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
        mbedtls_rsa_context *rsa = NULL;
        status = iotex_psa_rsa_load_representation( attributes->core.type,
                                                      key_buffer,
                                                      key_buffer_size,
                                                      &rsa );
        if( status != PSA_SUCCESS )
            goto rsa_exit;

        if( output_size < mbedtls_rsa_get_len( rsa ) )
        {
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            goto rsa_exit;
        }
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */
        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT)
            status = mbedtls_to_psa_error(
                    mbedtls_rsa_pkcs1_encrypt( rsa,
                                               mbedtls_psa_get_random,
                                               MBEDTLS_PSA_RANDOM_STATE,
                                               input_length,
                                               input,
                                               output ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT */
        }
        else
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
            status = mbedtls_to_psa_error(
                         psa_rsa_oaep_set_padding_mode( alg, rsa ) );
            if( status != PSA_SUCCESS )
                goto rsa_exit;

            status = mbedtls_to_psa_error(
                mbedtls_rsa_rsaes_oaep_encrypt( rsa,
                                                mbedtls_psa_get_random,
                                                MBEDTLS_PSA_RANDOM_STATE,
                                                salt, salt_length,
                                                input_length,
                                                input,
                                                output ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP */
        }
        else
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
rsa_exit:
        if( status == PSA_SUCCESS )
            *output_length = mbedtls_rsa_get_len( rsa );

        mbedtls_rsa_free( rsa );
        mbedtls_free( rsa );
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */
    }
    else
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;

#else
    (void) key_buffer;
    (void) key_buffer_size;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    return PSA_ERROR_NOT_SUPPORTED;
#endif

}

psa_status_t iotex_crypto_acceleration_asymmetric_decrypt( const psa_key_attributes_t *attributes,
                                             const uint8_t *key_buffer,
                                             size_t key_buffer_size,
                                             psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             const uint8_t *salt,
                                             size_t salt_length,
                                             uint8_t *output,
                                             size_t output_size,
                                             size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	// TODO:
	status = iotex_acc_lib_psa_hash_compute( operation, alg );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

    *output_length = 0;

    if( attributes->core.type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
        mbedtls_rsa_context *rsa = NULL;
        status = iotex_psa_rsa_load_representation( attributes->core.type,
                                                      key_buffer,
                                                      key_buffer_size,
                                                      &rsa );
        if( status != PSA_SUCCESS )
            goto rsa_exit;

        if( input_length != mbedtls_rsa_get_len( rsa ) )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto rsa_exit;
        }
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */

        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT)
            status = mbedtls_to_psa_error(
                mbedtls_rsa_pkcs1_decrypt( rsa,
                                           mbedtls_psa_get_random,
                                           MBEDTLS_PSA_RANDOM_STATE,
                                           output_length,
                                           input,
                                           output,
                                           output_size ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT */
        }
        else
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
            status = mbedtls_to_psa_error(
                         psa_rsa_oaep_set_padding_mode( alg, rsa ) );
            if( status != PSA_SUCCESS )
                goto rsa_exit;

            status = mbedtls_to_psa_error(
                mbedtls_rsa_rsaes_oaep_decrypt( rsa,
                                                mbedtls_psa_get_random,
                                                MBEDTLS_PSA_RANDOM_STATE,
                                                salt, salt_length,
                                                output_length,
                                                input,
                                                output,
                                                output_size ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP */
        }
        else
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
rsa_exit:
        mbedtls_rsa_free( rsa );
        mbedtls_free( rsa );
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */
    }
    else
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
#else
    (void) key_buffer;
    (void) key_buffer_size;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    return PSA_ERROR_NOT_SUPPORTED;
#endif
}

#endif
#endif

