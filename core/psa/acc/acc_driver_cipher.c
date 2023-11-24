#include <string.h>
#include "include/common.h"
#include "include/iotex/platform.h"

#define IOTEX_PSA_CRYPTO_C
#define IOTEX_PSA_CRYPTO_ACCELERATION_ENABLE
#define IOTEX_CRYPTO_CIPHER_ACCELETATION_SUPPORT

#if defined(IOTEX_PSA_CRYPTO_C)
#if defined(IOTEX_PSA_CRYPTO_ACCELERATION_ENABLE) && defined(IOTEX_CRYPTO_CIPHER_ACCELETATION_SUPPORT)
#include <server/crypto/psa_crypto_core.h>
#include <server/crypto/psa_crypto_cipher.h>
#if defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)
#include "include/mbedtls/cipher.h"
#endif

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
                mbedtls_cipher_update( (mbedtls_cipher_context_t *)ctx,
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
        		mbedtls_cipher_update( (mbedtls_cipher_context_t *)ctx, input,
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

psa_status_t iotex_crypto_acceleration_cipher_setup( iotex_psa_cipher_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, uint8_t cipher_operation )
{
#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	// TODO:
    status = iotex_acc_lib_psa_cipher_setup( operation, attributes, key_buffer, key_buffer_size, alg );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)
	int ret;
	size_t key_bits;
	const iotex_cipher_info_t *cipher_info = NULL;
	psa_key_type_t key_type = attributes->core.type;

	(void)key_buffer_size;

	mbedtls_cipher_init( (mbedtls_cipher_context_t *)&operation->ctx.cipher );

	operation->alg = alg;
	key_bits = attributes->core.bits;
	cipher_info = iotex_cipher_info_from_psa( alg, key_type, key_bits, NULL );
	if( cipher_info == NULL )
		return( PSA_ERROR_NOT_SUPPORTED );

	ret = mbedtls_cipher_setup( (mbedtls_cipher_context_t *)&operation->ctx.cipher, (mbedtls_cipher_info_t *)cipher_info );
	if( ret != 0 )
		goto exit;

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
	if( key_type == PSA_KEY_TYPE_DES && key_bits == 128 )
	{
		/* Two-key Triple-DES is 3-key Triple-DES with K1=K3 */
		uint8_t keys[24];
		memcpy( keys, key_buffer, 16 );
		memcpy( keys + 16, key_buffer, 8 );
		ret = mbedtls_cipher_setkey( &operation->ctx.cipher,
									 keys,
									 192, cipher_operation );
	}
	else
#endif
	{
		ret = mbedtls_cipher_setkey( (mbedtls_cipher_context_t *)&operation->ctx.cipher, key_buffer, (int) key_bits, cipher_operation );
	}
	if( ret != 0 )
		goto exit;

#if defined(IOTEX_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
	defined(IOTEX_PSA_BUILTIN_ALG_CBC_PKCS7)
	switch( alg )
	{
		case PSA_ALG_CBC_NO_PADDING:
			ret = mbedtls_cipher_set_padding_mode( (mbedtls_cipher_context_t *)&operation->ctx.cipher, MBEDTLS_PADDING_NONE );
			break;
		case PSA_ALG_CBC_PKCS7:
			ret = mbedtls_cipher_set_padding_mode( (mbedtls_cipher_context_t *)&operation->ctx.cipher, MBEDTLS_PADDING_PKCS7 );
			break;
		default:
			/* The algorithm doesn't involve padding. */
			ret = 0;
			break;
	}
	if( ret != 0 )
		goto exit;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING ||
		  MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7 */

	operation->block_length = ( PSA_ALG_IS_STREAM_CIPHER( alg ) ? 1 :
								PSA_BLOCK_CIPHER_BLOCK_LENGTH( key_type ) );
	operation->iv_length = PSA_CIPHER_IV_LENGTH( key_type, alg );

    exit:
        return( iotex_to_psa_error( ret ) );
#else
        (void) operation;
        (void) alg;
        return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_cipher_set_iv( iotex_psa_cipher_operation_t *operation, const uint8_t *iv, size_t iv_length )
{
#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	// TODO:
    status = iotex_acc_lib_psa_cipher_set_iv( operation, iv, iv_length );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)
    if( iv_length != operation->iv_length )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( iotex_to_psa_error( mbedtls_cipher_set_iv( (mbedtls_cipher_context_t *)&operation->ctx.cipher, iv, iv_length ) ) );
#else
        (void) operation;
        (void) alg;
        return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_cipher_update( iotex_psa_cipher_operation_t *operation, const uint8_t *input, size_t input_length, uint8_t *output, size_t output_size, size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	// TODO:
    status = iotex_acc_lib_psa_cipher_update( operation, input, input_lenght, output, output_size, output_lenght );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

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
            mbedtls_cipher_update( (mbedtls_cipher_context_t *)&operation->ctx.cipher, input,
                                   input_length, output, output_length ) );
        if( *output_length > output_size )
            return( PSA_ERROR_CORRUPTION_DETECTED );
    }

    return( status );
#else
        (void) operation;
        (void) alg;
        return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_cipher_finish( iotex_psa_cipher_operation_t *operation, uint8_t *output, size_t output_size, size_t *output_length )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	// TODO:
    status = iotex_acc_lib_psa_cipher_update( operation, input, input_lenght, output, output_size, output_lenght );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

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
        mbedtls_cipher_finish( (mbedtls_cipher_context_t *)&operation->ctx.cipher, temp_output_buffer, output_length ) );
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
#else
        (void) operation;
        (void) alg;
        return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_cipher_abort( iotex_psa_cipher_operation_t *operation )
{
#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	// TODO:
    iotex_acc_lib_psa_cipher_abort( operation );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)
    /* Sanity check (shouldn't happen: operation->alg should
     * always have been initialized to a valid value). */
    if( ! PSA_ALG_IS_CIPHER( operation->alg ) )
        return( PSA_ERROR_BAD_STATE );

    mbedtls_cipher_free( (mbedtls_cipher_context_t *)&operation->ctx.cipher );

    return( PSA_SUCCESS );
#else
        (void) operation;

        return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_cipher_encrypt( const psa_key_attributes_t *attributes,
														const uint8_t *key_buffer, size_t key_buffer_size,
														psa_algorithm_t alg,
														const uint8_t *iv, size_t iv_length,
														const uint8_t *input, size_t input_length,
														uint8_t *output, size_t output_size, size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_psa_cipher_operation_t operation = IOTEX_PSA_CIPHER_OPERATION_INIT;
    size_t update_output_length, finish_output_length;

    status = iotex_crypto_acceleration_cipher_setup( &operation, attributes, key_buffer, key_buffer_size, alg, 1 );
    if( status != PSA_SUCCESS )
        goto exit;

    if( iv_length > 0 )
    {
        status = iotex_crypto_acceleration_cipher_set_iv( &operation, iv, iv_length );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    status = iotex_crypto_acceleration_cipher_update( &operation, input, input_length,
                                        output, output_size,
                                        &update_output_length );
    if( status != PSA_SUCCESS )
        goto exit;

    status = iotex_crypto_acceleration_cipher_finish( &operation,
                                        output + update_output_length,
                                        output_size - update_output_length,
                                        &finish_output_length );
    if( status != PSA_SUCCESS )
        goto exit;

    *output_length = update_output_length + finish_output_length;

exit:
    if( status == PSA_SUCCESS )
        status = iotex_crypto_acceleration_cipher_abort( &operation );
    else
    	iotex_crypto_acceleration_cipher_abort( &operation );

    return( status );
}

psa_status_t iotex_crypto_acceleration_cipher_decrypt( const psa_key_attributes_t *attributes,
										const uint8_t *key_buffer, size_t key_buffer_size,
										psa_algorithm_t alg,
										const uint8_t *input, size_t input_length,
										uint8_t *output, size_t output_size, size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_psa_cipher_operation_t operation = IOTEX_PSA_CIPHER_OPERATION_INIT;
    size_t olength, accumulated_length;

    status = iotex_crypto_acceleration_cipher_setup( &operation, attributes, key_buffer, key_buffer_size, alg, 0 );
    if( status != PSA_SUCCESS )
        goto exit;

    if( operation.iv_length > 0 )
    {
        status = iotex_crypto_acceleration_cipher_set_iv( &operation,
                                            input, operation.iv_length );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    status = iotex_crypto_acceleration_cipher_update( &operation, input + operation.iv_length,
                                        input_length - operation.iv_length,
                                        output, output_size, &olength );
    if( status != PSA_SUCCESS )
        goto exit;

    accumulated_length = olength;

    status = iotex_crypto_acceleration_cipher_finish( &operation, output + accumulated_length,
                                        output_size - accumulated_length,
                                        &olength );
    if( status != PSA_SUCCESS )
        goto exit;

    *output_length = accumulated_length + olength;

exit:
    if ( status == PSA_SUCCESS )
        status = iotex_crypto_acceleration_cipher_abort( &operation );
    else
    	iotex_crypto_acceleration_cipher_abort( &operation );

    return( status );
}
#endif
#endif

