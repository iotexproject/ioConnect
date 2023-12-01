#include "include/common.h"

#if defined(IOTEX_PSA_CRYPTO_C)

#include "include/server/crypto.h"
#include "include/server/crypto_values.h"
#include "include/server/crypto/psa_crypto_core.h"
#include "include/server/crypto/psa_crypto_random_impl.h"
#include "include/server/crypto/psa_crypto_rsa.h"
#include "include/server/crypto/psa_crypto_hash.h"

#include <stdlib.h>
#include <string.h>
#include "include/iotex/platform.h"
#if !defined(IOTEX_PLATFORM_C)
#define iotex_calloc calloc
#define iotex_free   free
#endif

#include "include/iotex/rsa.h"
#include "include/iotex/error.h"
#include "include/iotex/pk.h"
#include "include/server/pk_wrap.h"

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS) || \
    defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)

/* Mbed TLS doesn't support non-byte-aligned key sizes (i.e. key sizes
 * that are not a multiple of 8) well. For example, there is only
 * iotex_rsa_get_len(), which returns a number of bytes, and no
 * way to return the exact bit size of a key.
 * To keep things simple, reject non-byte-aligned key sizes. */
static psa_status_t psa_check_rsa_key_byte_aligned(
    const iotex_rsa_context *rsa )
{
    iotex_mpi n;
    psa_status_t status;
    iotex_mpi_init( &n );
    status = iotex_to_psa_error(
        iotex_rsa_export( rsa, &n, NULL, NULL, NULL, NULL ) );
    if( status == PSA_SUCCESS )
    {
        if( iotex_mpi_bitlen( &n ) % 8 != 0 )
            status = PSA_ERROR_NOT_SUPPORTED;
    }
    iotex_mpi_free( &n );
    return( status );
}

psa_status_t iotex_psa_rsa_load_representation(
    psa_key_type_t type, const uint8_t *data, size_t data_length,
    iotex_rsa_context **p_rsa )
{
    psa_status_t status;
    iotex_pk_context ctx;
    size_t bits;
    iotex_pk_init( &ctx );

    /* Parse the data. */
    if( PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
        status = iotex_to_psa_error(
            iotex_pk_parse_key( &ctx, data, data_length, NULL, 0,
                iotex_psa_get_random, IOTEX_PSA_RANDOM_STATE ) );
    else
        status = iotex_to_psa_error(
            iotex_pk_parse_public_key( &ctx, data, data_length ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* We have something that the pkparse module recognizes. If it is a
     * valid RSA key, store it. */
    if( iotex_pk_get_type( &ctx ) != IOTEX_PK_RSA )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* The size of an RSA key doesn't have to be a multiple of 8. Mbed TLS
     * supports non-byte-aligned key sizes, but not well. For example,
     * iotex_rsa_get_len() returns the key size in bytes, not in bits. */
    bits = PSA_BYTES_TO_BITS( iotex_rsa_get_len( iotex_pk_rsa( ctx ) ) );
    if( bits > PSA_VENDOR_RSA_MAX_KEY_BITS )
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = psa_check_rsa_key_byte_aligned( iotex_pk_rsa( ctx ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Copy out the pointer to the RSA context, and reset the PK context
     * such that pk_free doesn't free the RSA context we just grabbed. */
    *p_rsa = iotex_pk_rsa( ctx );
    ctx.pk_info = NULL;

exit:
    iotex_pk_free( &ctx );
    return( status );
}
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS) ||
        * defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) ||
        * defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */

#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)

psa_status_t iotex_psa_rsa_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits )
{
    psa_status_t status;
    iotex_rsa_context *rsa = NULL;

    /* Parse input */
    status = iotex_psa_rsa_load_representation( attributes->core.type,
                                                  data,
                                                  data_length,
                                                  &rsa );
    if( status != PSA_SUCCESS )
        goto exit;

    *bits = (psa_key_bits_t) PSA_BYTES_TO_BITS( iotex_rsa_get_len( rsa ) );

    /* Re-export the data to PSA export format, such that we can store export
     * representation in the key slot. Export representation in case of RSA is
     * the smallest representation that's allowed as input, so a straight-up
     * allocation of the same size as the input buffer will be large enough. */
    status = iotex_psa_rsa_export_key( attributes->core.type,
                                         rsa,
                                         key_buffer,
                                         key_buffer_size,
                                         key_buffer_length );
exit:
    /* Always free the RSA object */
    iotex_rsa_free( rsa );
    iotex_free( rsa );

    return( status );
}

psa_status_t iotex_psa_rsa_export_key( psa_key_type_t type,
                                         iotex_rsa_context *rsa,
                                         uint8_t *data,
                                         size_t data_size,
                                         size_t *data_length )
{
#if defined(IOTEX_PK_WRITE_C)
    int ret;
    iotex_pk_context pk;
    uint8_t *pos = data + data_size;

    iotex_pk_init( &pk );
    pk.pk_info = &iotex_rsa_info;
    pk.pk_ctx = rsa;

    /* PSA Crypto API defines the format of an RSA key as a DER-encoded
     * representation of the non-encrypted PKCS#1 RSAPrivateKey for a
     * private key and of the RFC3279 RSAPublicKey for a public key. */
    if( PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
        ret = iotex_pk_write_key_der( &pk, data, data_size );
    else
        ret = iotex_pk_write_pubkey( &pos, data, &pk );

    if( ret < 0 )
    {
        /* Clean up in case pk_write failed halfway through. */
        memset( data, 0, data_size );
        return( iotex_to_psa_error( ret ) );
    }

    /* The iotex_pk_xxx functions write to the end of the buffer.
     * Move the data to the beginning and erase remaining data
     * at the original location. */
    if( 2 * (size_t) ret <= data_size )
    {
        memcpy( data, data + data_size - ret, ret );
        memset( data + data_size - ret, 0, ret );
    }
    else if( (size_t) ret < data_size )
    {
        memmove( data, data + data_size - ret, ret );
        memset( data + ret, 0, data_size - ret );
    }

    *data_length = ret;
    return( PSA_SUCCESS );
#else
    (void) type;
    (void) rsa;
    (void) data;
    (void) data_size;
    (void) data_length;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* IOTEX_PK_WRITE_C */
}

psa_status_t iotex_psa_rsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_rsa_context *rsa = NULL;

    status = iotex_psa_rsa_load_representation(
                 attributes->core.type, key_buffer, key_buffer_size, &rsa );
    if( status != PSA_SUCCESS )
        return( status );

    status = iotex_psa_rsa_export_key( PSA_KEY_TYPE_RSA_PUBLIC_KEY,
                                         rsa,
                                         data,
                                         data_size,
                                         data_length );

    iotex_rsa_free( rsa );
    iotex_free( rsa );

    return( status );
}
#endif /* defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) ||
        * defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */

#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) && \
    defined(IOTEX_GENPRIME)
static psa_status_t psa_rsa_read_exponent( const uint8_t *domain_parameters,
                                           size_t domain_parameters_size,
                                           int *exponent )
{
    size_t i;
    uint32_t acc = 0;

    if( domain_parameters_size == 0 )
    {
        *exponent = 65537;
        return( PSA_SUCCESS );
    }

    /* Mbed TLS encodes the public exponent as an int. For simplicity, only
     * support values that fit in a 32-bit integer, which is larger than
     * int on just about every platform anyway. */
    if( domain_parameters_size > sizeof( acc ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    for( i = 0; i < domain_parameters_size; i++ )
        acc = ( acc << 8 ) | domain_parameters[i];
    if( acc > INT_MAX )
        return( PSA_ERROR_NOT_SUPPORTED );
    *exponent = acc;
    return( PSA_SUCCESS );
}

psa_status_t iotex_psa_rsa_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{
    psa_status_t status;
    iotex_rsa_context rsa;
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    int exponent;

    status = psa_rsa_read_exponent( attributes->domain_parameters,
                                    attributes->domain_parameters_size,
                                    &exponent );
    if( status != PSA_SUCCESS )
        return( status );

    iotex_rsa_init( &rsa );
    ret = iotex_rsa_gen_key( &rsa,
                               iotex_psa_get_random,
                               IOTEX_PSA_RANDOM_STATE,
                               (unsigned int)attributes->core.bits,
                               exponent );
    if( ret != 0 )
        return( iotex_to_psa_error( ret ) );

    status = iotex_psa_rsa_export_key( attributes->core.type,
                                         &rsa, key_buffer, key_buffer_size,
                                         key_buffer_length );
    iotex_rsa_free( &rsa );

    return( status );
}
#endif /* defined(IOTEX_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR)
        * defined(IOTEX_GENPRIME) */

/****************************************************************/
/* Sign/verify hashes */
/****************************************************************/

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS)

/* Decode the hash algorithm from alg and store the mbedtls encoding in
 * md_alg. Verify that the hash length is acceptable. */
static psa_status_t psa_rsa_decode_md_type( psa_algorithm_t alg,
                                            size_t hash_length,
                                            iotex_md_type_t *md_alg )
{
    psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH( alg );
    const iotex_md_info_t *md_info = iotex_md_info_from_psa( hash_alg );
    *md_alg = iotex_md_get_type( md_info );

    /* The Mbed TLS RSA module uses an unsigned int for hash length
     * parameters. Validate that it fits so that we don't risk an
     * overflow later. */
#if SIZE_MAX > UINT_MAX
    if( hash_length > UINT_MAX )
        return( PSA_ERROR_INVALID_ARGUMENT );
#endif

    /* For signatures using a hash, the hash length must be correct. */
    if( alg != PSA_ALG_RSA_PKCS1V15_SIGN_RAW )
    {
        if( md_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( iotex_md_get_size( md_info ) != hash_length )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

    return( PSA_SUCCESS );
}

psa_status_t iotex_psa_rsa_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_rsa_context *rsa = NULL;
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    iotex_md_type_t md_alg;

    status = iotex_psa_rsa_load_representation( attributes->core.type,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &rsa );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
    if( status != PSA_SUCCESS )
        goto exit;

    if( signature_size < iotex_rsa_get_len( rsa ) )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
    if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
    {
        ret = iotex_rsa_set_padding( rsa, IOTEX_RSA_PKCS_V15,
                                       IOTEX_MD_NONE );
        if( ret == 0 )
        {
            ret = iotex_rsa_pkcs1_sign( rsa,
                                          iotex_psa_get_random,
                                          IOTEX_PSA_RANDOM_STATE,
                                          md_alg,
                                          (unsigned int) hash_length,
                                          hash,
                                          signature );
        }
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS)
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        ret = iotex_rsa_set_padding( rsa, IOTEX_RSA_PKCS_V21, md_alg );

        if( ret == 0 )
        {
            ret = iotex_rsa_rsassa_pss_sign( rsa,
                                               iotex_psa_get_random,
                                               IOTEX_PSA_RANDOM_STATE,
                                               IOTEX_MD_NONE,
                                               (unsigned int) hash_length,
                                               hash,
                                               signature );
        }
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_PSS */
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if( ret == 0 )
        *signature_length = iotex_rsa_get_len( rsa );
    status = iotex_to_psa_error( ret );

exit:
    iotex_rsa_free( rsa );
    iotex_free( rsa );

    return( status );
}

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS)
static int rsa_pss_expected_salt_len( psa_algorithm_t alg,
                                      const iotex_rsa_context *rsa,
                                      size_t hash_length )
{
    if( PSA_ALG_IS_RSA_PSS_ANY_SALT( alg ) )
        return( IOTEX_RSA_SALT_LEN_ANY );
    /* Otherwise: standard salt length, i.e. largest possible salt length
     * up to the hash length. */
    int klen = (int) iotex_rsa_get_len( rsa ); // known to fit
    int hlen = (int) hash_length; // known to fit
    int room = klen - 2 - hlen;
    if( room < 0 )
        return( 0 ); // there is no valid signature in this case anyway
    else if( room > hlen )
        return( hlen );
    else
        return( room );
}
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_PSS */

psa_status_t iotex_psa_rsa_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    iotex_rsa_context *rsa = NULL;
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    iotex_md_type_t md_alg;

    status = iotex_psa_rsa_load_representation( attributes->core.type,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &rsa );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
    if( status != PSA_SUCCESS )
        goto exit;

    if( signature_length != iotex_rsa_get_len( rsa ) )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
    if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
    {
        ret = iotex_rsa_set_padding( rsa, IOTEX_RSA_PKCS_V15,
                                       IOTEX_MD_NONE );
        if( ret == 0 )
        {
            ret = iotex_rsa_pkcs1_verify( rsa,
                                            md_alg,
                                            (unsigned int) hash_length,
                                            hash,
                                            signature );
        }
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS)
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        ret = iotex_rsa_set_padding( rsa, IOTEX_RSA_PKCS_V21, md_alg );
        if( ret == 0 )
        {
            int slen = rsa_pss_expected_salt_len( alg, rsa, hash_length );
            ret = iotex_rsa_rsassa_pss_verify_ext( rsa,
                                                     md_alg,
                                                     (unsigned) hash_length,
                                                     hash,
                                                     md_alg,
                                                     slen,
                                                     signature );
        }
    }
    else
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_PSS */
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Mbed TLS distinguishes "invalid padding" from "valid padding but
     * the rest of the signature is invalid". This has little use in
     * practice and PSA doesn't report this distinction. */
    status = ( ret == IOTEX_ERR_RSA_INVALID_PADDING ) ?
             PSA_ERROR_INVALID_SIGNATURE :
             iotex_to_psa_error( ret );

exit:
    iotex_rsa_free( rsa );
    iotex_free( rsa );

    return( status );
}

#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_PSS) */

/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
static int psa_rsa_oaep_set_padding_mode( psa_algorithm_t alg,
                                          iotex_rsa_context *rsa )
{
    psa_algorithm_t hash_alg = PSA_ALG_RSA_OAEP_GET_HASH( alg );
    const iotex_md_info_t *md_info = iotex_md_info_from_psa( hash_alg );
    iotex_md_type_t md_alg = iotex_md_get_type( md_info );

    return( iotex_rsa_set_padding( rsa, IOTEX_RSA_PKCS_V21, md_alg ) );
}
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) */

psa_status_t iotex_psa_asymmetric_encrypt( const psa_key_attributes_t *attributes,
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
    (void) key_buffer;
    (void) key_buffer_size;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    if( PSA_KEY_TYPE_IS_RSA( attributes->core.type ) )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
        iotex_rsa_context *rsa = NULL;
        status = iotex_psa_rsa_load_representation( attributes->core.type,
                                                      key_buffer,
                                                      key_buffer_size,
                                                      &rsa );
        if( status != PSA_SUCCESS )
            goto rsa_exit;

        if( output_size < iotex_rsa_get_len( rsa ) )
        {
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            goto rsa_exit;
        }
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) */
        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT)
            status = iotex_to_psa_error(
                    iotex_rsa_pkcs1_encrypt( rsa,
                                               iotex_psa_get_random,
                                               IOTEX_PSA_RANDOM_STATE,
                                               input_length,
                                               input,
                                               output ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT */
        }
        else
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
            status = iotex_to_psa_error(
                         psa_rsa_oaep_set_padding_mode( alg, rsa ) );
            if( status != PSA_SUCCESS )
                goto rsa_exit;

            status = iotex_to_psa_error(
                iotex_rsa_rsaes_oaep_encrypt( rsa,
                                                iotex_psa_get_random,
                                                IOTEX_PSA_RANDOM_STATE,
                                                salt, salt_length,
                                                input_length,
                                                input,
                                                output ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_OAEP */
        }
        else
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
rsa_exit:
        if( status == PSA_SUCCESS )
            *output_length = iotex_rsa_get_len( rsa );

        iotex_rsa_free( rsa );
        iotex_free( rsa );
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) */
    }
    else
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

psa_status_t iotex_psa_asymmetric_decrypt( const psa_key_attributes_t *attributes,
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
    (void) key_buffer;
    (void) key_buffer_size;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    *output_length = 0;

    if( attributes->core.type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
        iotex_rsa_context *rsa = NULL;
        status = iotex_psa_rsa_load_representation( attributes->core.type,
                                                      key_buffer,
                                                      key_buffer_size,
                                                      &rsa );
        if( status != PSA_SUCCESS )
            goto rsa_exit;

        if( input_length != iotex_rsa_get_len( rsa ) )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto rsa_exit;
        }
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) */

        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT)
            status = iotex_to_psa_error(
                iotex_rsa_pkcs1_decrypt( rsa,
                                           iotex_psa_get_random,
                                           IOTEX_PSA_RANDOM_STATE,
                                           output_length,
                                           input,
                                           output,
                                           output_size ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT */
        }
        else
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
            status = iotex_to_psa_error(
                         psa_rsa_oaep_set_padding_mode( alg, rsa ) );
            if( status != PSA_SUCCESS )
                goto rsa_exit;

            status = iotex_to_psa_error(
                iotex_rsa_rsaes_oaep_decrypt( rsa,
                                                iotex_psa_get_random,
                                                IOTEX_PSA_RANDOM_STATE,
                                                salt, salt_length,
                                                output_length,
                                                input,
                                                output,
                                                output_size ) );
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif /* IOTEX_PSA_BUILTIN_ALG_RSA_OAEP */
        }
        else
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }

#if defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP)
rsa_exit:
        iotex_rsa_free( rsa );
        iotex_free( rsa );
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_RSA_OAEP) */
    }
    else
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

#endif /* IOTEX_PSA_CRYPTO_C */
