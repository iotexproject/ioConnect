/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include "include/common.h"

#if defined(IOTEX_PSA_CRYPTO_C)

#include "include/server/crypto/psa_crypto_cipher.h"
#include "include/server/crypto/psa_crypto_core.h"
#include "include/server/crypto/psa_crypto_random_impl.h"

#include "include/iotex/cipher.h"
#include "include/iotex/error.h"

#include <string.h>

const iotex_cipher_info_t *iotex_cipher_info_from_psa(
    psa_algorithm_t alg,
    psa_key_type_t key_type,
    size_t key_bits,
    iotex_cipher_id_t* cipher_id )
{
    iotex_cipher_mode_t mode;
    iotex_cipher_id_t cipher_id_tmp;

    if( PSA_ALG_IS_AEAD( alg ) )
        alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 );

    if( PSA_ALG_IS_CIPHER( alg ) || PSA_ALG_IS_AEAD( alg ) )
    {
        switch( alg )
        {
#if defined(IOTEX_PSA_BUILTIN_ALG_STREAM_CIPHER)
            case PSA_ALG_STREAM_CIPHER:
                mode = IOTEX_MODE_STREAM;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_CTR)
            case PSA_ALG_CTR:
                mode = IOTEX_MODE_CTR;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_CFB)
            case PSA_ALG_CFB:
                mode = IOTEX_MODE_CFB;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_OFB)
            case PSA_ALG_OFB:
                mode = IOTEX_MODE_OFB;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_ECB_NO_PADDING)
            case PSA_ALG_ECB_NO_PADDING:
                mode = IOTEX_MODE_ECB;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_CBC_NO_PADDING)
            case PSA_ALG_CBC_NO_PADDING:
                mode = IOTEX_MODE_CBC;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_CBC_PKCS7)
            case PSA_ALG_CBC_PKCS7:
                mode = IOTEX_MODE_CBC;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM_STAR_NO_TAG)
            case PSA_ALG_CCM_STAR_NO_TAG:
                mode = IOTEX_MODE_CCM_STAR_NO_TAG;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_CCM)
            case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
                mode = IOTEX_MODE_CCM;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_GCM)
            case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
                mode = IOTEX_MODE_GCM;
                break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
            case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
                mode = IOTEX_MODE_CHACHAPOLY;
                break;
#endif
            default:
                return( NULL );
        }
    }
    else if( alg == PSA_ALG_CMAC )
        mode = IOTEX_MODE_ECB;
    else
        return( NULL );

    switch( key_type )
    {
#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_AES)
        case PSA_KEY_TYPE_AES:
            cipher_id_tmp = IOTEX_CIPHER_ID_AES;
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ARIA)
        case PSA_KEY_TYPE_ARIA:
            cipher_id_tmp = IOTEX_CIPHER_ID_ARIA;
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_DES)
        case PSA_KEY_TYPE_DES:
            /* key_bits is 64 for Single-DES, 128 for two-key Triple-DES,
             * and 192 for three-key Triple-DES. */
            if( key_bits == 64 )
                cipher_id_tmp = IOTEX_CIPHER_ID_DES;
            else
                cipher_id_tmp = IOTEX_CIPHER_ID_3DES;
            /* mbedtls doesn't recognize two-key Triple-DES as an algorithm,
             * but two-key Triple-DES is functionally three-key Triple-DES
             * with K1=K3, so that's how we present it to mbedtls. */
            if( key_bits == 128 )
                key_bits = 192;
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_CAMELLIA)
        case PSA_KEY_TYPE_CAMELLIA:
            cipher_id_tmp = IOTEX_CIPHER_ID_CAMELLIA;
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_CHACHA20)
        case PSA_KEY_TYPE_CHACHA20:
            cipher_id_tmp = IOTEX_CIPHER_ID_CHACHA20;
            break;
#endif
        default:
            return( NULL );
    }
    if( cipher_id != NULL )
        *cipher_id = cipher_id_tmp;

    return( iotex_cipher_info_from_values( cipher_id_tmp,
                                             (int) key_bits, mode ) );
}

#if defined(IOTEX_PSA_BUILTIN_CIPHER)

static psa_status_t psa_cipher_setup(
    iotex_psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    iotex_operation_t cipher_operation )
{
    int ret = 0;
    size_t key_bits;
    const iotex_cipher_info_t *cipher_info = NULL;
    psa_key_type_t key_type = attributes->core.type;

    (void)key_buffer_size;

    iotex_cipher_init( &operation->ctx.cipher );
    memset((void *)&operation->ctx.cipher, 0, sizeof(iotex_cipher_context_t));
    operation->alg = alg;
    key_bits = attributes->core.bits;
    cipher_info = iotex_cipher_info_from_psa( alg, key_type,
                                                key_bits, NULL );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    ret = iotex_cipher_setup( &operation->ctx.cipher, cipher_info );
    if( ret != 0 )
        goto exit;

#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_DES)
    if( key_type == PSA_KEY_TYPE_DES && key_bits == 128 )
    {
        /* Two-key Triple-DES is 3-key Triple-DES with K1=K3 */
        uint8_t keys[24];
        memcpy( keys, key_buffer, 16 );
        memcpy( keys + 16, key_buffer, 8 );
        ret = iotex_cipher_setkey( &operation->ctx.cipher,
                                     keys,
                                     192, cipher_operation );
    }
    else
#endif
    {
        ret = iotex_cipher_setkey( &operation->ctx.cipher, key_buffer,
                                     (int) key_bits, cipher_operation );
    }
    if( ret != 0 )        
        goto exit;

#if defined(IOTEX_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(IOTEX_PSA_BUILTIN_ALG_CBC_PKCS7)
    switch( alg )
    {
        case PSA_ALG_CBC_NO_PADDING:
            ret = iotex_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   IOTEX_PADDING_NONE );
            break;
        case PSA_ALG_CBC_PKCS7:
            ret = iotex_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   IOTEX_PADDING_PKCS7 );
            break;
        default:
            /* The algorithm doesn't involve padding. */
            ret = 0;
            break;
    }
    if( ret != 0 )
        goto exit;
#endif /* IOTEX_PSA_BUILTIN_ALG_CBC_NO_PADDING ||
          IOTEX_PSA_BUILTIN_ALG_CBC_PKCS7 */
    
    operation->block_length = ( PSA_ALG_IS_STREAM_CIPHER( alg ) ? 1 :
                                PSA_BLOCK_CIPHER_BLOCK_LENGTH( key_type ) );
    operation->iv_length = PSA_CIPHER_IV_LENGTH( key_type, alg );
    
exit:
    return( iotex_to_psa_error( ret ) );
}

psa_status_t iotex_psa_cipher_encrypt_setup(
    iotex_psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, attributes,
                              key_buffer, key_buffer_size,
                              alg, IOTEX_ENCRYPT ) );
}

psa_status_t iotex_psa_cipher_decrypt_setup(
    iotex_psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, attributes,
                              key_buffer, key_buffer_size,
                              alg, IOTEX_DECRYPT ) );
}

psa_status_t iotex_psa_cipher_set_iv(
    iotex_psa_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length )
{
    if( iv_length != operation->iv_length )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( iotex_to_psa_error(
                iotex_cipher_set_iv( &operation->ctx.cipher,
                                       iv, iv_length ) ) );
}

#if defined(IOTEX_PSA_BUILTIN_ALG_ECB_NO_PADDING)
/** Process input for which the algorithm is set to ECB mode.
 *
 * This requires manual processing, since the PSA API is defined as being
 * able to process arbitrary-length calls to psa_cipher_update() with ECB mode,
 * but the underlying iotex_cipher_update only takes full blocks.
 *
 * \param ctx           The mbedtls cipher context to use. It must have been
 *                      set up for ECB.
 * \param[in] input     The input plaintext or ciphertext to process.
 * \param input_length  The number of bytes to process from \p input.
 *                      This does not need to be aligned to a block boundary.
 *                      If there is a partial block at the end of the input,
 *                      it is stored in \p ctx for future processing.
 * \param output        The buffer where the output is written. It must be
 *                      at least `BS * floor((p + input_length) / BS)` bytes
 *                      long, where `p` is the number of bytes in the
 *                      unprocessed partial block in \p ctx (with
 *                      `0 <= p <= BS - 1`) and `BS` is the block size.
 * \param output_length On success, the number of bytes written to \p output.
 *                      \c 0 on error.
 *
 * \return #PSA_SUCCESS or an error from a hardware accelerator
 */
static psa_status_t psa_cipher_update_ecb(
    iotex_cipher_context_t *ctx,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t block_size = ctx->cipher_info->block_size;
    size_t internal_output_length = 0;
    *output_length = 0;

    if( input_length == 0 )
    {
        status = PSA_SUCCESS;
        goto exit;
    }

    if( ctx->unprocessed_len > 0 )
    {
        /* Fill up to block size, and run the block if there's a full one. */
        size_t bytes_to_copy = block_size - ctx->unprocessed_len;

        if( input_length < bytes_to_copy )
            bytes_to_copy = input_length;

        memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ),
                input, bytes_to_copy );
        input_length -= bytes_to_copy;
        input += bytes_to_copy;
        ctx->unprocessed_len += bytes_to_copy;

        if( ctx->unprocessed_len == block_size )
        {
            status = iotex_to_psa_error(
                iotex_cipher_update( ctx,
                                       ctx->unprocessed_data,
                                       block_size,
                                       output, &internal_output_length ) );

            if( status != PSA_SUCCESS )
                goto exit;

            output += internal_output_length;
            *output_length += internal_output_length;
            ctx->unprocessed_len = 0;
        }
    }

    while( input_length >= block_size )
    {
        /* Run all full blocks we have, one by one */
        status = iotex_to_psa_error(
            iotex_cipher_update( ctx, input,
                                   block_size,
                                   output, &internal_output_length ) );

        if( status != PSA_SUCCESS )
            goto exit;

        input_length -= block_size;
        input += block_size;

        output += internal_output_length;
        *output_length += internal_output_length;
    }

    if( input_length > 0 )
    {
        /* Save unprocessed bytes for later processing */
        memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ),
                input, input_length );
        ctx->unprocessed_len += input_length;
    }

    status = PSA_SUCCESS;

exit:
    return( status );
}
#endif /* IOTEX_PSA_BUILTIN_ALG_ECB_NO_PADDING */

psa_status_t iotex_psa_cipher_update(
    iotex_psa_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t expected_output_size;

    if( ! PSA_ALG_IS_STREAM_CIPHER( operation->alg ) )
    {
        /* Take the unprocessed partial block left over from previous
         * update calls, if any, plus the input to this call. Remove
         * the last partial block, if any. You get the data that will be
         * output in this call. */
        expected_output_size =
            ( operation->ctx.cipher.unprocessed_len + input_length )
            / operation->block_length * operation->block_length;
    }
    else
    {
        expected_output_size = input_length;
    }

    if( output_size < expected_output_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(IOTEX_PSA_BUILTIN_ALG_ECB_NO_PADDING)
    if( operation->alg == PSA_ALG_ECB_NO_PADDING )
    {
        /* iotex_cipher_update has an API inconsistency: it will only
        * process a single block at a time in ECB mode. Abstract away that
        * inconsistency here to match the PSA API behaviour. */
        status = psa_cipher_update_ecb( &operation->ctx.cipher,
                                        input,
                                        input_length,
                                        output,
                                        output_length );
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_ECB_NO_PADDING */
    {
        status = iotex_to_psa_error(
            iotex_cipher_update( &operation->ctx.cipher, input,
                                   input_length, output, output_length ) );
        if( *output_length > output_size )
            return( PSA_ERROR_CORRUPTION_DETECTED );
    }

    return( status );
}

psa_status_t iotex_psa_cipher_finish(
    iotex_psa_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t temp_output_buffer[IOTEX_MAX_BLOCK_LENGTH];

    if( operation->ctx.cipher.unprocessed_len != 0 )
    {
        if( operation->alg == PSA_ALG_ECB_NO_PADDING ||
            operation->alg == PSA_ALG_CBC_NO_PADDING )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    }

    status = iotex_to_psa_error(
        iotex_cipher_finish( &operation->ctx.cipher,
                               temp_output_buffer,
                               output_length ) );
    if( status != PSA_SUCCESS )
        goto exit;

    if( *output_length == 0 )
        ; /* Nothing to copy. Note that output may be NULL in this case. */
    else if( output_size >= *output_length )
        memcpy( output, temp_output_buffer, *output_length );
    else
        status = PSA_ERROR_BUFFER_TOO_SMALL;

exit:
    iotex_platform_zeroize( temp_output_buffer,
                              sizeof( temp_output_buffer ) );

    return( status );
}

psa_status_t iotex_psa_cipher_abort(
    iotex_psa_cipher_operation_t *operation )
{
    /* Sanity check (shouldn't happen: operation->alg should
     * always have been initialized to a valid value). */
    if( ! PSA_ALG_IS_CIPHER( operation->alg ) )
        return( PSA_ERROR_BAD_STATE );

    iotex_cipher_free( &operation->ctx.cipher );

    return( PSA_SUCCESS );
}

psa_status_t iotex_psa_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv,
    size_t iv_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_psa_cipher_operation_t operation = IOTEX_PSA_CIPHER_OPERATION_INIT;
    size_t update_output_length, finish_output_length;

    status = iotex_psa_cipher_encrypt_setup( &operation, attributes,
                                               key_buffer, key_buffer_size,
                                               alg );
    if( status != PSA_SUCCESS )
        goto exit;

    if( iv_length > 0 )
    {
        status = iotex_psa_cipher_set_iv( &operation, iv, iv_length );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    status = iotex_psa_cipher_update( &operation, input, input_length,
                                        output, output_size,
                                        &update_output_length );
    if( status != PSA_SUCCESS )
        goto exit;

    status = iotex_psa_cipher_finish( &operation,
                                        output + update_output_length,
                                        output_size - update_output_length,
                                        &finish_output_length );
    if( status != PSA_SUCCESS )
        goto exit;

    *output_length = update_output_length + finish_output_length;

exit:
    if( status == PSA_SUCCESS )
        status = iotex_psa_cipher_abort( &operation );
    else
        iotex_psa_cipher_abort( &operation );

    return( status );
}

psa_status_t iotex_psa_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_psa_cipher_operation_t operation = IOTEX_PSA_CIPHER_OPERATION_INIT;
    size_t olength, accumulated_length;

    status = iotex_psa_cipher_decrypt_setup( &operation, attributes,
                                               key_buffer, key_buffer_size,
                                               alg );
    if( status != PSA_SUCCESS )
        goto exit;

    if( operation.iv_length > 0 )
    {
        status = iotex_psa_cipher_set_iv( &operation,
                                            input, operation.iv_length );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    status = iotex_psa_cipher_update( &operation, input + operation.iv_length,
                                        input_length - operation.iv_length,
                                        output, output_size, &olength );
    if( status != PSA_SUCCESS )
        goto exit;

    accumulated_length = olength;

    status = iotex_psa_cipher_finish( &operation, output + accumulated_length,
                                        output_size - accumulated_length,
                                        &olength );
    if( status != PSA_SUCCESS )
        goto exit;

    *output_length = accumulated_length + olength;

exit:
    if ( status == PSA_SUCCESS )
        status = iotex_psa_cipher_abort( &operation );
    else
        iotex_psa_cipher_abort( &operation );

    return( status );
}
#endif /* IOTEX_PSA_BUILTIN_CIPHER */

#endif /* IOTEX_PSA_CRYPTO_C */
