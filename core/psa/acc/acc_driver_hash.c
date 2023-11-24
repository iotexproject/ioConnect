#include <string.h>
#include "include/common.h"
#include "include/iotex/platform.h"

#if defined(IOTEX_PSA_CRYPTO_C)
#if defined(IOTEX_PSA_CRYPTO_ACCELERATION_ENABLE) && defined(IOTEX_CRYPTO_SHA_ACCELETATION_SUPPORT)
#include <server/crypto/psa_crypto_core.h>
#include <server/crypto/psa_crypto_hash.h>
#if defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)
#include "include/mbedtls/sha1.h"
#include "include/mbedtls/sha256.h"
#include "include/mbedtls/sha512.h"
#endif

psa_status_t iotex_crypto_acceleration_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	// TODO:
	status = iotex_acc_lib_psa_hash_compute( operation, alg );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

	iotex_psa_hash_operation_t operation = IOTEX_PSA_HASH_OPERATION_INIT;
	psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;

	*hash_length = hash_size;
	status = iotex_psa_hash_setup( &operation, alg );
	if( status != PSA_SUCCESS )
		goto exit;
	status = iotex_psa_hash_update( &operation, input, input_length );
	if( status != PSA_SUCCESS )
		goto exit;
	status = iotex_psa_hash_finish( &operation, hash, hash_size, hash_length );
	if( status != PSA_SUCCESS )
		goto exit;

exit:
	abort_status = iotex_psa_hash_abort( &operation );
	if( status == PSA_SUCCESS )
		return( abort_status );
	else
		return( status );
#else
        (void) operation;
        (void) alg;
        return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_hash_setup(iotex_psa_hash_operation_t *operation, psa_algorithm_t alg )
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	int ret;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
		// TODO:
        status = iotex_acc_lib_psa_hash_setup( operation, alg );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

        /* A context must be freshly initialized before it can be set up. */
        if( operation->alg != 0 )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        switch( alg )
        {
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
            case PSA_ALG_SHA_1:
                mbedtls_sha1_init( &operation->ctx.sha1 );
                ret = mbedtls_sha1_starts( &operation->ctx.sha1 );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
            case PSA_ALG_SHA_224:
                mbedtls_sha256_init( (mbedtls_sha256_context *)&operation->ctx.sha256 );
                ret = mbedtls_sha256_starts( (mbedtls_sha256_context *)&operation->ctx.sha256, 1 );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
            case PSA_ALG_SHA_256:
                mbedtls_sha256_init( (mbedtls_sha256_context *)&operation->ctx.sha256 );
                ret = mbedtls_sha256_starts( (mbedtls_sha256_context *)&operation->ctx.sha256, 0 );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
            case PSA_ALG_SHA_384:
                mbedtls_sha512_init( &operation->ctx.sha512 );
                ret = mbedtls_sha512_starts( &operation->ctx.sha512, 1 );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
            case PSA_ALG_SHA_512:
                mbedtls_sha512_init( &operation->ctx.sha512 );
                ret = mbedtls_sha512_starts( &operation->ctx.sha512, 0 );
                break;
    #endif
            default:
                return( PSA_ALG_IS_HASH( alg ) ?
                        PSA_ERROR_NOT_SUPPORTED :
                        PSA_ERROR_INVALID_ARGUMENT );
        }
        if( ret == 0 )
            operation->alg = alg;
        else
            iotex_psa_hash_abort( operation );
        return( iotex_to_psa_error( ret ) );
#else
        (void) operation;
        (void) alg;
        status = PSA_ERROR_NOT_SUPPORTED;
#endif

        return status;
}

psa_status_t iotex_crypto_acceleration_hash_update(iotex_psa_hash_operation_t *operation, const uint8_t *input, size_t input_length )
{
	int ret;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
		// TODO:
        status = iotex_acc_lib_psa_hash_update( operation, input, input_length );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

        switch( operation->alg )
        {
    #if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
            case PSA_ALG_MD5:
                ret = mbedtls_md5_update( &operation->ctx.md5,
                                              input, input_length );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
            case PSA_ALG_RIPEMD160:
                ret = mbedtls_ripemd160_update( &operation->ctx.ripemd160,
                                                    input, input_length );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
            case PSA_ALG_SHA_1:
                ret = mbedtls_sha1_update( &operation->ctx.sha1,
                                               input, input_length );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
            case PSA_ALG_SHA_224:
                ret = mbedtls_sha256_update( (mbedtls_sha256_context *)&operation->ctx.sha256, input, input_length );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
            case PSA_ALG_SHA_256:
                ret = mbedtls_sha256_update( (mbedtls_sha256_context *)&operation->ctx.sha256, input, input_length );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
            case PSA_ALG_SHA_384:
                ret = mbedtls_sha512_update( (mbedtls_sha512_context *)&operation->ctx.sha512, input, input_length );
                break;
    #endif
    #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
            case PSA_ALG_SHA_512:
                ret = mbedtls_sha512_update( (mbedtls_sha512_context *)&operation->ctx.sha512, input, input_length );
                break;
    #endif
            default:
                (void) input;
                (void) input_length;
                return( PSA_ERROR_BAD_STATE );
        }

        return( iotex_to_psa_error( ret ) );
#else
        (void) operation;
        (void) alg;
        return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_hash_finish(iotex_psa_hash_operation_t *operation, uint8_t *hash, size_t hash_size, size_t *hash_length )
{
    psa_status_t status;
	int ret;

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
		// TODO:
		status = iotex_acc_lib_psa_hash_finish( operation, hash, hash_size, hash_length );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

	size_t actual_hash_length = PSA_HASH_LENGTH( operation->alg );

	/* Fill the output buffer with something that isn't a valid hash
	 * (barring an attack on the hash and deliberately-crafted input),
	 * in case the caller doesn't check the return status properly. */
	*hash_length = hash_size;
	/* If hash_size is 0 then hash may be NULL and then the
	 * call to memset would have undefined behavior. */
	if( hash_size != 0 )
		memset( hash, '!', hash_size );

	if( hash_size < actual_hash_length )
	{
		status = PSA_ERROR_BUFFER_TOO_SMALL;
		goto exit;
	}

	switch( operation->alg )
	{
#if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
		case PSA_ALG_MD5:
			ret = mbedtls_md5_finish( &operation->ctx.md5, hash );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
		case PSA_ALG_RIPEMD160:
			ret = mbedtls_ripemd160_finish( &operation->ctx.ripemd160, hash );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
		case PSA_ALG_SHA_1:
			ret = mbedtls_sha1_finish( &operation->ctx.sha1, hash );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
		case PSA_ALG_SHA_224:
			ret = mbedtls_sha256_finish( (mbedtls_sha256_context *)&operation->ctx.sha256, hash );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
		case PSA_ALG_SHA_256:
			ret = mbedtls_sha256_finish( (mbedtls_sha256_context *)&operation->ctx.sha256, hash );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
		case PSA_ALG_SHA_384:
			ret = mbedtls_sha512_finish( (mbedtls_sha512_context *)&operation->ctx.sha512, hash );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
		case PSA_ALG_SHA_512:
			ret = mbedtls_sha512_finish( (mbedtls_sha512_context *)&operation->ctx.sha512, hash );
			break;
#endif
		default:
			(void) hash;
			return( PSA_ERROR_BAD_STATE );
	}
	status = iotex_to_psa_error( ret );

exit:
	if( status == PSA_SUCCESS )
		*hash_length = actual_hash_length;
	return( status );
#else
	(void) operation;
	(void) alg;
	return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t iotex_crypto_acceleration_hash_abort( iotex_psa_hash_operation_t *operation )
{

#if defined(IOTEX_CRYPTO_USE_ACCELERATION_LIB)
	psa_status_t status;

	// TODO:
	status = iotex_acc_lib_psa_hash_abort( operation );
#elif defined(IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS)

	switch( operation->alg )
	{
		case 0:
			/* The object has (apparently) been initialized but it is not
			 * in use. It's ok to call abort on such an object, and there's
			 * nothing to do. */
			break;
#if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
		case PSA_ALG_MD5:
			mbedtls_md5_free( &operation->ctx.md5 );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
		case PSA_ALG_RIPEMD160:
			mbedtls_ripemd160_free( &operation->ctx.ripemd160 );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
		case PSA_ALG_SHA_1:
			mbedtls_sha1_free( &operation->ctx.sha1 );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
		case PSA_ALG_SHA_224:
			mbedtls_sha256_free( (mbedtls_sha256_context *)&operation->ctx.sha256 );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
		case PSA_ALG_SHA_256:
			mbedtls_sha256_free( (mbedtls_sha256_context *)&operation->ctx.sha256 );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
		case PSA_ALG_SHA_384:
			mbedtls_sha512_free( (mbedtls_sha512_context *)&operation->ctx.sha512 );
			break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
		case PSA_ALG_SHA_512:
			mbedtls_sha512_free( (mbedtls_sha512_context *)&operation->ctx.sha512 );
			break;
#endif
		default:
			return( PSA_ERROR_BAD_STATE );
	}
	operation->alg = 0;
	return( PSA_SUCCESS );
#else
	(void) operation;

	return PSA_ERROR_NOT_SUPPORTED;
#endif
}

#endif
#endif

