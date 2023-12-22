#include "include/common.h"

#include "include/iotex/platform.h"

#if defined(IOTEX_PSA_CRYPTO_C)

#include "include/server/crypto.h"
#include "include/server/crypto/psa_crypto_core.h"
#include "include/server/crypto/psa_crypto_hash.h"

#include "include/iotex/error.h"
#include <string.h>

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS) || \
    defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
const iotex_md_info_t *iotex_md_info_from_psa( psa_algorithm_t alg )
{
    switch( alg )
    {
#if defined(IOTEX_MD5_C)
        case PSA_ALG_MD5:
            return( &iotex_md5_info );
#endif
#if defined(IOTEX_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            return( &iotex_ripemd160_info );
#endif
#if defined(IOTEX_SHA1_C)
        case PSA_ALG_SHA_1:
            return( &iotex_sha1_info );
#endif
#if defined(IOTEX_SHA224_C)
        case PSA_ALG_SHA_224:
            return( &iotex_sha224_info );
#endif
#if defined(IOTEX_SHA256_C)
        case PSA_ALG_SHA_256:
            return( &iotex_sha256_info );
#endif
#if defined(IOTEX_SHA384_C)
        case PSA_ALG_SHA_384:
            return( &iotex_sha384_info );
#endif
#if defined(IOTEX_SHA512_C)
        case PSA_ALG_SHA_512:
            return( &iotex_sha512_info );
#endif
        default:
            return( NULL );
    }
}
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */

#if defined(IOTEX_PSA_BUILTIN_HASH)
psa_status_t iotex_psa_hash_abort(
    iotex_psa_hash_operation_t *operation )
{
    switch( operation->alg )
    {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;
#if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            iotex_md5_free( &operation->ctx.md5 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            iotex_ripemd160_free( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            iotex_sha1_free( &operation->ctx.sha1 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            iotex_sha256_free( &operation->ctx.sha256 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            iotex_sha256_free( &operation->ctx.sha256 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            iotex_sha512_free( &operation->ctx.sha512 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            iotex_sha512_free( &operation->ctx.sha512 );
            break;
#endif
        default:
            return( PSA_ERROR_BAD_STATE );
    }
    operation->alg = 0;
    return( PSA_SUCCESS );
}

psa_status_t iotex_psa_hash_setup(
    iotex_psa_hash_operation_t *operation,
    psa_algorithm_t alg )
{
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if( operation->alg != 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    switch( alg )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            iotex_md5_init( &operation->ctx.md5 );
            ret = iotex_md5_starts( &operation->ctx.md5 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            iotex_ripemd160_init( &operation->ctx.ripemd160 );
            ret = iotex_ripemd160_starts( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            iotex_sha1_init( &operation->ctx.sha1 );
            ret = iotex_sha1_starts( &operation->ctx.sha1 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            iotex_sha256_init( &operation->ctx.sha256 );
            ret = iotex_sha256_starts( &operation->ctx.sha256, 1 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            iotex_sha256_init( &operation->ctx.sha256 );
            ret = iotex_sha256_starts( &operation->ctx.sha256, 0 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            iotex_sha512_init( &operation->ctx.sha512 );
            ret = iotex_sha512_starts( &operation->ctx.sha512, 1 );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            iotex_sha512_init( &operation->ctx.sha512 );
            ret = iotex_sha512_starts( &operation->ctx.sha512, 0 );
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
}

 psa_status_t iotex_psa_hash_clone(
     const iotex_psa_hash_operation_t *source_operation,
     iotex_psa_hash_operation_t *target_operation )
{
     switch( source_operation->alg )
     {
         case 0:
             return( PSA_ERROR_BAD_STATE );
 #if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
         case PSA_ALG_MD5:
             iotex_md5_clone( &target_operation->ctx.md5,
                                &source_operation->ctx.md5 );
             break;
 #endif
 #if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
         case PSA_ALG_RIPEMD160:
             iotex_ripemd160_clone( &target_operation->ctx.ripemd160,
                                      &source_operation->ctx.ripemd160 );
             break;
 #endif
 #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
         case PSA_ALG_SHA_1:
             iotex_sha1_clone( &target_operation->ctx.sha1,
                                 &source_operation->ctx.sha1 );
             break;
 #endif
 #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
         case PSA_ALG_SHA_224:
             iotex_sha256_clone( &target_operation->ctx.sha256,
                                   &source_operation->ctx.sha256 );
             break;
 #endif
 #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
         case PSA_ALG_SHA_256:
             iotex_sha256_clone( &target_operation->ctx.sha256,
                                   &source_operation->ctx.sha256 );
             break;
 #endif
 #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
         case PSA_ALG_SHA_384:
             iotex_sha512_clone( &target_operation->ctx.sha512,
                                   &source_operation->ctx.sha512 );
             break;
 #endif
 #if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
         case PSA_ALG_SHA_512:
             iotex_sha512_clone( &target_operation->ctx.sha512,
                                   &source_operation->ctx.sha512 );
             break;
 #endif
         default:
             (void) source_operation;
             (void) target_operation;
             return( PSA_ERROR_NOT_SUPPORTED );
     }

     target_operation->alg = source_operation->alg;
     return( PSA_SUCCESS );
}

psa_status_t iotex_psa_hash_update(
    iotex_psa_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;

    switch( operation->alg )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            ret = iotex_md5_update( &operation->ctx.md5,
                                          input, input_length );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            ret = iotex_ripemd160_update( &operation->ctx.ripemd160,
                                                input, input_length );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            ret = iotex_sha1_update( &operation->ctx.sha1,
                                           input, input_length );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            ret = iotex_sha256_update( &operation->ctx.sha256,
                                             input, input_length );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            ret = iotex_sha256_update( &operation->ctx.sha256,
                                             input, input_length );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            ret = iotex_sha512_update( &operation->ctx.sha512,
                                             input, input_length );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            ret = iotex_sha512_update( &operation->ctx.sha512,
                                             input, input_length );
            break;
#endif
        default:
            (void) input;
            (void) input_length;
            return( PSA_ERROR_BAD_STATE );
    }

    return( iotex_to_psa_error( ret ) );
}

psa_status_t iotex_psa_hash_finish(
    iotex_psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length )
{
    psa_status_t status;
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
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
            ret = iotex_md5_finish( &operation->ctx.md5, hash );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            ret = iotex_ripemd160_finish( &operation->ctx.ripemd160, hash );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            ret = iotex_sha1_finish( &operation->ctx.sha1, hash );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            ret = iotex_sha256_finish( &operation->ctx.sha256, hash );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            ret = iotex_sha256_finish( &operation->ctx.sha256, hash );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            ret = iotex_sha512_finish( &operation->ctx.sha512, hash );
            break;
#endif
#if defined(IOTEX_PSA_BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            ret = iotex_sha512_finish( &operation->ctx.sha512, hash );
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
}

psa_status_t iotex_psa_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    iotex_psa_hash_operation_t operation = IOTEX_PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
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

}
#endif /* IOTEX_PSA_BUILTIN_HASH */

#endif /* IOTEX_PSA_CRYPTO_C */
