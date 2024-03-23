#include "include/common.h"

#if defined(IOTEX_PSA_CRYPTO_C)

#include "include/server/crypto/psa_crypto_aead.h"
#include "include/server/crypto/psa_crypto_core.h"

#include <string.h>
#include "include/iotex/platform.h"
#if !defined(IOTEX_PLATFORM_C)
#define iotex_calloc calloc
#define iotex_free   free
#endif

#include "include/iotex/ccm.h"
#include "include/iotex/chachapoly.h"
#include "include/iotex/cipher.h"
#include "include/iotex/gcm.h"
#include "include/iotex/error.h"

static psa_status_t psa_aead_setup(
    iotex_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t key_bits;
    const iotex_cipher_info_t *cipher_info;
    iotex_cipher_id_t cipher_id;
    size_t full_tag_length = 0;

    ( void ) key_buffer_size;

    key_bits = attributes->core.bits;

    cipher_info = iotex_cipher_info_from_psa( alg,
                                                attributes->core.type, key_bits,
                                                &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            operation->alg = PSA_ALG_CCM;
            full_tag_length = 16;
            /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16.
             * The call to iotex_ccm_encrypt_and_tag or
             * iotex_ccm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( attributes->core.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            iotex_ccm_init( &operation->ctx.ccm );
            status = iotex_to_psa_error(
                iotex_ccm_setkey( &operation->ctx.ccm, cipher_id,
                                    key_buffer, (unsigned int) key_bits ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */

#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            operation->alg = PSA_ALG_GCM;
            full_tag_length = 16;
            /* GCM allows the following tag lengths: 4, 8, 12, 13, 14, 15, 16.
             * The call to iotex_gcm_crypt_and_tag or
             * iotex_gcm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( attributes->core.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            iotex_gcm_init( &operation->ctx.gcm );
            status = iotex_to_psa_error(
                iotex_gcm_setkey( &operation->ctx.gcm, cipher_id,
                                    key_buffer, (unsigned int) key_bits ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */

#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            operation->alg = PSA_ALG_CHACHA20_POLY1305;
            full_tag_length = 16;
            /* We only support the default tag length. */
            if( alg != PSA_ALG_CHACHA20_POLY1305 )
                return( PSA_ERROR_NOT_SUPPORTED );

            iotex_chachapoly_init( &operation->ctx.chachapoly );
            status = iotex_to_psa_error(
                iotex_chachapoly_setkey( &operation->ctx.chachapoly,
                                           key_buffer ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */

        default:
            (void) status;
            (void) key_buffer;
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( PSA_AEAD_TAG_LENGTH( attributes->core.type,
                             key_bits, alg )
        > full_tag_length )
        return( PSA_ERROR_INVALID_ARGUMENT );

    operation->key_type = psa_get_key_type( attributes );

    operation->tag_length = PSA_AEAD_TAG_LENGTH( operation->key_type,
                                                 key_bits,
                                                 alg );

    return( PSA_SUCCESS );
}

psa_status_t iotex_psa_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_psa_aead_operation_t operation = IOTEX_PSA_AEAD_OPERATION_INIT;
    uint8_t *tag;

    status = psa_aead_setup( &operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status != PSA_SUCCESS )
        goto exit;

    /* For all currently supported modes, the tag is at the end of the
     * ciphertext. */
    if( ciphertext_size < ( plaintext_length + operation.tag_length ) )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    tag = ciphertext + plaintext_length;

#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
    if( operation.alg == PSA_ALG_CCM )
    {
        status = iotex_to_psa_error(
            iotex_ccm_encrypt_and_tag( &operation.ctx.ccm,
                                         plaintext_length,
                                         nonce, nonce_length,
                                         additional_data,
                                         additional_data_length,
                                         plaintext, ciphertext,
                                         tag, operation.tag_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
    if( operation.alg == PSA_ALG_GCM )
    {
        status = iotex_to_psa_error(
            iotex_gcm_crypt_and_tag( &operation.ctx.gcm,
                                       IOTEX_GCM_ENCRYPT,
                                       plaintext_length,
                                       nonce, nonce_length,
                                       additional_data, additional_data_length,
                                       plaintext, ciphertext,
                                       operation.tag_length, tag ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation.alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = iotex_to_psa_error(
            iotex_chachapoly_encrypt_and_tag( &operation.ctx.chachapoly,
                                                plaintext_length,
                                                nonce,
                                                additional_data,
                                                additional_data_length,
                                                plaintext,
                                                ciphertext,
                                                tag ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) tag;
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *ciphertext_length = plaintext_length + operation.tag_length;

exit:
    iotex_psa_aead_abort( &operation );

    return( status );
}

/* Locate the tag in a ciphertext buffer containing the encrypted data
 * followed by the tag. Return the length of the part preceding the tag in
 * *plaintext_length. This is the size of the plaintext in modes where
 * the encrypted data has the same size as the plaintext, such as
 * CCM and GCM. */
static psa_status_t psa_aead_unpadded_locate_tag( size_t tag_length,
                                                  const uint8_t *ciphertext,
                                                  size_t ciphertext_length,
                                                  size_t plaintext_size,
                                                  const uint8_t **p_tag )
{
    size_t payload_length;
    if( tag_length > ciphertext_length )
        return( PSA_ERROR_INVALID_ARGUMENT );
    payload_length = ciphertext_length - tag_length;
    if( payload_length > plaintext_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    *p_tag = ciphertext + payload_length;
    return( PSA_SUCCESS );
}

psa_status_t iotex_psa_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_psa_aead_operation_t operation = IOTEX_PSA_AEAD_OPERATION_INIT;
    const uint8_t *tag = NULL;

    status = psa_aead_setup( &operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_aead_unpadded_locate_tag( operation.tag_length,
                                           ciphertext, ciphertext_length,
                                           plaintext_size, &tag );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
    if( operation.alg == PSA_ALG_CCM )
    {
        status = iotex_to_psa_error(
            iotex_ccm_auth_decrypt( &operation.ctx.ccm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      ciphertext, plaintext,
                                      tag, operation.tag_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
    if( operation.alg == PSA_ALG_GCM )
    {
        status = iotex_to_psa_error(
            iotex_gcm_auth_decrypt( &operation.ctx.gcm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      tag, operation.tag_length,
                                      ciphertext, plaintext ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation.alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = iotex_to_psa_error(
           iotex_chachapoly_auth_decrypt( &operation.ctx.chachapoly,
                                             ciphertext_length - operation.tag_length,
                                             nonce,
                                             additional_data,
                                             additional_data_length,
                                             tag,
                                             ciphertext,
                                             plaintext ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - operation.tag_length;

exit:
    iotex_psa_aead_abort( &operation );

    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - operation.tag_length;
    return( status );
}

/* Set the key and algorithm for a multipart authenticated encryption
 * operation. */
psa_status_t iotex_psa_aead_encrypt_setup(
    iotex_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_aead_setup( operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status == PSA_SUCCESS )
        operation->is_encrypt = 1;

    return ( status );
}

/* Set the key and algorithm for a multipart authenticated decryption
 * operation. */
psa_status_t iotex_psa_aead_decrypt_setup(
    iotex_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_aead_setup( operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status == PSA_SUCCESS )
        operation->is_encrypt = 0;

    return ( status );
}

/* Set a nonce for the multipart AEAD operation*/
psa_status_t iotex_psa_aead_set_nonce(
    iotex_psa_aead_operation_t *operation,
    const uint8_t *nonce,
    size_t nonce_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status = iotex_to_psa_error(
                 iotex_gcm_starts( &operation->ctx.gcm,
                                     operation->is_encrypt ?
                                     IOTEX_GCM_ENCRYPT : IOTEX_GCM_DECRYPT,
                                     nonce,
                                     nonce_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        status = iotex_to_psa_error(
                   iotex_ccm_starts( &operation->ctx.ccm,
                                       operation->is_encrypt ?
                                       IOTEX_CCM_ENCRYPT : IOTEX_CCM_DECRYPT,
                                       nonce,
                                       nonce_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        /* Note - ChaChaPoly allows an 8 byte nonce, but we would have to
         * allocate a buffer in the operation, copy the nonce to it and pad
         * it, so for now check the nonce is 12 bytes, as
         * iotex_chachapoly_starts() assumes it can read 12 bytes from the
         * passed in buffer. */
        if( nonce_length != 12 )
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }

        status = iotex_to_psa_error(
           iotex_chachapoly_starts( &operation->ctx.chachapoly,
                                      nonce,
                                      operation->is_encrypt ?
                                      IOTEX_CHACHAPOLY_ENCRYPT :
                                      IOTEX_CHACHAPOLY_DECRYPT ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) operation;
        ( void ) nonce;
        ( void ) nonce_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    return( status );
}

 /* Declare the lengths of the message and additional data for AEAD. */
psa_status_t iotex_psa_aead_set_lengths(
    iotex_psa_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length )
{
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        return( iotex_to_psa_error(
                         iotex_ccm_set_lengths( &operation->ctx.ccm,
                                                 ad_length,
                                                 plaintext_length,
                                                 operation->tag_length ) ) );

    }
#else /* IOTEX_PSA_BUILTIN_ALG_CCM */
    ( void ) operation;
    ( void ) ad_length;
    ( void ) plaintext_length;
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */

    return ( PSA_SUCCESS );
}

/* Pass additional data to an active multipart AEAD operation. */
psa_status_t iotex_psa_aead_update_ad(
    iotex_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status = iotex_to_psa_error(
            iotex_gcm_update_ad( &operation->ctx.gcm, input, input_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        status = iotex_to_psa_error(
            iotex_ccm_update_ad( &operation->ctx.ccm, input, input_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        status = iotex_to_psa_error(
           iotex_chachapoly_update_aad( &operation->ctx.chachapoly,
                                          input,
                                          input_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) operation;
        ( void ) input;
        ( void ) input_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    return ( status );
}

/* Encrypt or decrypt a message fragment in an active multipart AEAD
 * operation.*/
psa_status_t iotex_psa_aead_update(
    iotex_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
    size_t update_output_length;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    update_output_length = input_length;

#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status =  iotex_to_psa_error(
            iotex_gcm_update( &operation->ctx.gcm,
                                input, input_length,
                                output, output_size,
                                &update_output_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        if( output_size < input_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = iotex_to_psa_error(
           iotex_ccm_update( &operation->ctx.ccm,
                               input, input_length,
                               output, output_size,
                               &update_output_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( output_size < input_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = iotex_to_psa_error(
           iotex_chachapoly_update( &operation->ctx.chachapoly,
                                      input_length,
                                      input,
                                      output ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) operation;
        ( void ) input;
        ( void ) output;
        ( void ) output_size;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *output_length = update_output_length;

    return( status );
}

/* Finish encrypting a message in a multipart AEAD operation. */
psa_status_t iotex_psa_aead_finish(
    iotex_psa_aead_operation_t *operation,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tag_size,
    size_t *tag_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t finish_output_size = 0;

    if( tag_size < operation->tag_length )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status =  iotex_to_psa_error(
            iotex_gcm_finish( &operation->ctx.gcm,
                                ciphertext, ciphertext_size, ciphertext_length,
                                tag, operation->tag_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        /* tag must be big enough to store a tag of size passed into set
         * lengths. */
        if( tag_size < operation->tag_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = iotex_to_psa_error(
                           iotex_ccm_finish( &operation->ctx.ccm,
                                               tag, operation->tag_length ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        /* Belt and braces. Although the above tag_size check should have
         * already done this, if we later start supporting smaller tag sizes
         * for chachapoly, then passing a tag buffer smaller than 16 into here
         * could cause a buffer overflow, so better safe than sorry. */
        if( tag_size < 16 )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = iotex_to_psa_error(
            iotex_chachapoly_finish( &operation->ctx.chachapoly,
                                       tag ) );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) ciphertext;
        ( void ) ciphertext_size;
        ( void ) ciphertext_length;
        ( void ) tag;
        ( void ) tag_size;
        ( void ) tag_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
    {
        /* This will be zero for all supported algorithms currently, but left
         * here for future support. */
        *ciphertext_length = finish_output_size;
        *tag_length = operation->tag_length;
    }

    return ( status );
}

/* Abort an AEAD operation */
psa_status_t iotex_psa_aead_abort(
   iotex_psa_aead_operation_t *operation )
{
    switch( operation->alg )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
        case PSA_ALG_CCM:
            iotex_ccm_free( &operation->ctx.ccm );
            break;
#endif /* IOTEX_PSA_BUILTIN_ALG_CCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
        case PSA_ALG_GCM:
            iotex_gcm_free( &operation->ctx.gcm );
            break;
#endif /* IOTEX_PSA_BUILTIN_ALG_GCM */
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_CHACHA20_POLY1305:
            iotex_chachapoly_free( &operation->ctx.chachapoly );
            break;
#endif /* IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    }

    operation->is_encrypt = 0;

    return( PSA_SUCCESS );
}

#endif /* IOTEX_PSA_CRYPTO_C */

