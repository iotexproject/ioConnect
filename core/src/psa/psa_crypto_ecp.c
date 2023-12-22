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

#include "include/iotex/platform.h"

#if defined(IOTEX_PSA_CRYPTO_C)

#include "include/server/crypto.h"
#include "include/server/crypto/psa_crypto_core.h"
#include "include/server/crypto/psa_crypto_ecp.h"
#include "include/server/crypto/psa_crypto_random_impl.h"
#include "include/server/crypto/psa_crypto_hash.h"

#include <stdlib.h>
#include <string.h>
#include "include/iotex/platform.h"
#if !defined(IOTEX_PLATFORM_C)
#define iotex_calloc calloc
#define iotex_free   free
#endif

#include "include/iotex/ecdsa.h"
#include "include/iotex/eddsa.h"
#include "include/iotex/ecp.h"
#include "include/iotex/error.h"

#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(IOTEX_PSA_BUILTIN_ALG_ECDSA) || \
    defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) || \
    defined(IOTEX_PSA_BUILTIN_ALG_ECDH)
psa_status_t iotex_psa_ecp_load_representation(
    psa_key_type_t type, size_t curve_bits,
    const uint8_t *data, size_t data_length,
    iotex_ecp_keypair **p_ecp )
{
    iotex_ecp_group_id grp_id = IOTEX_ECP_DP_NONE;
    psa_status_t status;
    iotex_ecp_keypair *ecp = NULL;
    size_t curve_bytes = data_length;
    int explicit_bits = ( curve_bits != 0 );

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) &&
        PSA_KEY_TYPE_ECC_GET_FAMILY( type ) != PSA_ECC_FAMILY_MONTGOMERY )
    {
        /* A Weierstrass public key is represented as:
         * - The byte 0x04;
         * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
         * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
         * So its data length is 2m+1 where m is the curve size in bits.
         */
        if( ( data_length & 1 ) == 0 )
            return( PSA_ERROR_INVALID_ARGUMENT );
        curve_bytes = data_length / 2;

        /* Montgomery public keys are represented in compressed format, meaning
         * their curve_bytes is equal to the amount of input. */

        /* Private keys are represented in uncompressed private random integer
         * format, meaning their curve_bytes is equal to the amount of input. */
    }
    
    if( explicit_bits )
    {
        /* With an explicit bit-size, the data must have the matching length. */
        if( curve_bytes != PSA_BITS_TO_BYTES( curve_bits ) )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
    else
    {
        /* We need to infer the bit-size from the data. Since the only
         * information we have is the length in bytes, the value of curve_bits
         * at this stage is rounded up to the nearest multiple of 8. */
        curve_bits = PSA_BYTES_TO_BITS( curve_bytes );
    }
    
    /* Allocate and initialize a key representation. */
    ecp = iotex_calloc( 1, sizeof( iotex_ecp_keypair ) );
    if( ecp == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    iotex_ecp_keypair_init( ecp );
    
    /* Load the group. */
    grp_id = iotex_ecc_group_of_psa( PSA_KEY_TYPE_ECC_GET_FAMILY( type ),
                                       curve_bits, !explicit_bits );
    if( grp_id == IOTEX_ECP_DP_NONE )
    {
        /* We can't distinguish between a nonsensical family/size combination
         * (which would warrant PSA_ERROR_INVALID_ARGUMENT) and a
         * well-regarded curve that Mbed TLS just doesn't know about (which
         * would warrant PSA_ERROR_NOT_SUPPORTED). For uniformity with how
         * curves that Mbed TLS knows about but for which support is disabled
         * at build time, return NOT_SUPPORTED. */
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    
    status = iotex_to_psa_error(
                iotex_ecp_group_load( &ecp->grp, grp_id ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Load the key material. */
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        /* Load the public value. */
        status = iotex_to_psa_error(
            iotex_ecp_point_read_binary( &ecp->grp, &ecp->Q,
                                           data,
                                           data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;
        /* Check that the point is on the curve. */
        status = iotex_to_psa_error(
            iotex_ecp_check_pubkey( &ecp->grp, &ecp->Q ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    else
    {
        /* Load and validate the secret value. */
        status = iotex_to_psa_error(
            iotex_ecp_read_key( ecp->grp.id,
                                  ecp,
                                  data,
                                  data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    *p_ecp = ecp;
exit:
    if( status != PSA_SUCCESS )
    {
        iotex_ecp_keypair_free( ecp );
        iotex_free( ecp );
    }

    return( status );
}
#endif /* defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) ||
        * defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) ||
        * defined(IOTEX_PSA_BUILTIN_ALG_ECDH) */

#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)

psa_status_t iotex_psa_ecp_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    psa_status_t status;

    iotex_ecp_keypair *ecp = NULL;

    /* Parse input */
    status = iotex_psa_ecp_load_representation( attributes->core.type,
                                                  attributes->core.bits,
                                                  data,
                                                  data_length,
                                                  &ecp );
    if( status != PSA_SUCCESS )
    {
        goto exit;
    }
    printf("iotex_psa_ecp_import_key 1\n");

    if( PSA_KEY_TYPE_ECC_GET_FAMILY( attributes->core.type ) ==
        PSA_ECC_FAMILY_MONTGOMERY )
        *bits = ecp->grp.nbits + 1;
    else
        *bits = ecp->grp.nbits;

    /* Re-export the data to PSA export format. There is currently no support
     * for other input formats then the export format, so this is a 1-1
     * copy operation. */
    status = iotex_psa_ecp_export_key( attributes->core.type,
                                         ecp,
                                         key_buffer,
                                         key_buffer_size,
                                         key_buffer_length );
exit:
    /* Always free the PK object (will also free contained ECP context) */
    iotex_ecp_keypair_free( ecp );
    iotex_free( ecp );

    return( status );
#else
    /* Copy the key material. */
    memcpy( key_buffer, data, data_length );
    *key_buffer_length = data_length;
    (void)key_buffer_size;

    iotex_ecp_calc_pub_key(PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->core.type), key_buffer, data_length);

    return( PSA_SUCCESS );    
#endif    
}

psa_status_t iotex_psa_ecp_export_key( psa_key_type_t type,
                                         iotex_ecp_keypair *ecp,
                                         uint8_t *data,
                                         size_t data_size,
                                         size_t *data_length )
{
    psa_status_t status;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        /* Check whether the public part is loaded */
        if( iotex_ecp_is_zero( &ecp->Q ) )
        {
            /* Calculate the public key */
            status = iotex_to_psa_error(
                iotex_ecp_mul( &ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G,
                                 iotex_psa_get_random,
                                 IOTEX_PSA_RANDOM_STATE ) );
            if( status != PSA_SUCCESS )
                return( status );
        }

        status = iotex_to_psa_error(
                    iotex_ecp_point_write_binary( &ecp->grp, &ecp->Q,
                                                    IOTEX_ECP_PF_UNCOMPRESSED,
                                                    data_length,
                                                    data,
                                                    data_size ) );
        if( status != PSA_SUCCESS )
            memset( data, 0, data_size );

        return( status );
    }
    else
    {
        if( data_size < PSA_BITS_TO_BYTES( ecp->grp.nbits ) )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        status = iotex_to_psa_error(
                    iotex_ecp_write_key( ecp,
                                           data,
                                           PSA_BITS_TO_BYTES( ecp->grp.nbits ) ) );                                       
        if( status == PSA_SUCCESS )
            *data_length = PSA_BITS_TO_BYTES( ecp->grp.nbits );
        else
            memset( data, 0, data_size );

        return( status );
    }  
}

psa_status_t iotex_psa_ecp_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS     
    iotex_ecp_keypair *ecp = NULL;

    status = iotex_psa_ecp_load_representation(
        attributes->core.type, attributes->core.bits,
        key_buffer, key_buffer_size, &ecp );
    if( status != PSA_SUCCESS )
        return( status );

    status = iotex_psa_ecp_export_key(
                 PSA_KEY_TYPE_ECC_PUBLIC_KEY(
                     PSA_KEY_TYPE_ECC_GET_FAMILY( attributes->core.type ) ),
                 ecp, data, data_size, data_length );
    iotex_ecp_keypair_free( ecp );
    iotex_free( ecp );

#else
    status = iotex_psa_ecp_export_key_from_raw_data( PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->core.type), key_buffer, data, data_length );
#endif    
    return( status );
}
#endif /* defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) ||
        * defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) */

#if defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR)
psa_status_t iotex_psa_ecp_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS    
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;

    psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY(
                                 attributes->core.type );
    iotex_ecp_group_id grp_id =
         iotex_ecc_group_of_psa( curve, attributes->core.bits, 0 );

    const iotex_ecp_curve_info *curve_info =
        iotex_ecp_curve_info_from_grp_id( grp_id );
    iotex_ecp_keypair ecp;

    if( attributes->domain_parameters_size != 0 )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( grp_id == IOTEX_ECP_DP_NONE || curve_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    iotex_ecp_keypair_init( &ecp );

#endif

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS    
    ret = iotex_ecp_gen_key( grp_id, &ecp,
                               iotex_psa_get_random,
                               IOTEX_PSA_RANDOM_STATE );
#else
    status = iotex_ecp_gen_key( PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->core.type), key_buffer, key_buffer_size );
#endif                               

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS            
    if( ret != 0 )
    {
        iotex_ecp_keypair_free( &ecp );
        return( iotex_to_psa_error( ret ) );
    }
#endif        

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS            
    status = iotex_to_psa_error(
        iotex_ecp_write_key( &ecp, key_buffer, key_buffer_size ) );

    iotex_ecp_keypair_free( &ecp );
#endif

    if( status == PSA_SUCCESS )
        *key_buffer_length = key_buffer_size;

    return( status );
}
#endif /* defined(IOTEX_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) */

/****************************************************************/
/* ECDSA sign/verify */
/****************************************************************/

#if defined(IOTEX_PSA_BUILTIN_ALG_ECDSA) || \
    defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
psa_status_t iotex_psa_ecdsa_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    iotex_ecp_keypair *ecp = NULL;
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    size_t curve_bytes;
    iotex_mpi r, s;

    status = iotex_psa_ecp_load_representation( attributes->core.type,
                                                  attributes->core.bits,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &ecp );
    if( status != PSA_SUCCESS )
        return( status );

    curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );

    iotex_mpi_init( &r );
    iotex_mpi_init( &s );

    if( signature_size < 2 * curve_bytes )
    {
        ret = IOTEX_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if( PSA_ALG_ECDSA_IS_DETERMINISTIC( alg ) )
    {
#if defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
        psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH( alg );
        const iotex_md_info_t *md_info = iotex_md_info_from_psa( hash_alg );
        iotex_md_type_t md_alg = iotex_md_get_type( md_info );
        IOTEX_MPI_CHK( iotex_ecdsa_sign_det_ext(
                             &ecp->grp, &r, &s,
                             &ecp->d, hash,
                             hash_length, md_alg,
                             iotex_psa_get_random,
                             IOTEX_PSA_RANDOM_STATE ) );
#else
       ret = IOTEX_ERR_ECP_FEATURE_UNAVAILABLE;
       goto cleanup;
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */
    }
    else
    {
        (void) alg;
        IOTEX_MPI_CHK( iotex_ecdsa_sign( &ecp->grp, &r, &s, &ecp->d,
                                             hash, hash_length,
                                             iotex_psa_get_random,
                                             IOTEX_PSA_RANDOM_STATE ) );
    }

    IOTEX_MPI_CHK( iotex_mpi_write_binary( &r,
                                               signature,
                                               curve_bytes ) );
    IOTEX_MPI_CHK( iotex_mpi_write_binary( &s,
                                               signature + curve_bytes,
                                               curve_bytes ) );
cleanup:
    iotex_mpi_free( &r );
    iotex_mpi_free( &s );
    if( ret == 0 )
        *signature_length = 2 * curve_bytes;

    iotex_ecp_keypair_free( ecp );
    iotex_free( ecp );

    return( iotex_to_psa_error( ret ) );
#else
    
    return iotex_ecdsa_sign( PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->core.type), 
                    key_buffer, key_buffer_size, 
                    hash, hash_length, 
                    signature, signature_length);

#endif    
}

psa_status_t iotex_psa_ecdsa_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS    

	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	iotex_ecp_keypair *ecp = NULL;
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    size_t curve_bytes;
    iotex_mpi r, s;

    (void)alg;

    status = iotex_psa_ecp_load_representation( attributes->core.type,
                                                  attributes->core.bits,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &ecp );
    if( status != PSA_SUCCESS )
        return( status );

    curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    iotex_mpi_init( &r );
    iotex_mpi_init( &s );

    if( signature_length != 2 * curve_bytes )
    {
        ret = IOTEX_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    IOTEX_MPI_CHK( iotex_mpi_read_binary( &r,
                                              signature,
                                              curve_bytes ) );
    IOTEX_MPI_CHK( iotex_mpi_read_binary( &s,
                                              signature + curve_bytes,
                                              curve_bytes ) );

    /* Check whether the public part is loaded. If not, load it. */
    if( iotex_ecp_is_zero( &ecp->Q ) )
    {
        IOTEX_MPI_CHK(
            iotex_ecp_mul( &ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G,
                             iotex_psa_get_random, IOTEX_PSA_RANDOM_STATE ) );
    }

    ret = iotex_ecdsa_verify( &ecp->grp, hash, hash_length,
                                &ecp->Q, &r, &s );

cleanup:
    iotex_mpi_free( &r );
    iotex_mpi_free( &s );
    iotex_ecp_keypair_free( ecp );
    iotex_free( ecp );

    return( iotex_to_psa_error( ret ) );
#else
    return iotex_ecdsa_verify( PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->core.type), 
                            key_buffer, key_buffer_size,
                            hash, hash_length, (uint8_t *)signature, signature_length);
#endif    
}

  
#endif /* defined(IOTEX_PSA_BUILTIN_ALG_ECDSA) || \
        * defined(IOTEX_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */

psa_status_t iotex_psa_eddsa_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{ 
    return iotex_eddsa_sign( PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->core.type), 
                    key_buffer, key_buffer_size, 
                    hash, hash_length, 
                    signature, signature_length);
} 

psa_status_t iotex_psa_eddsa_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    return iotex_eddsa_verify( PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->core.type), 
                            key_buffer, key_buffer_size,
                            hash, hash_length, (uint8_t *)signature, signature_length);    
}

#endif /* IOTEX_PSA_CRYPTO_C */
