/**
 * \file cipher_wrap.c
 *
 * \brief Generic cipher wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
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

#if defined(IOTEX_CIPHER_C)

#include "include/server/cipher_wrap.h"
#include "include/iotex/error.h"

#if defined(IOTEX_CHACHAPOLY_C)
#include "include/iotex/chachapoly.h"
#endif

#if defined(IOTEX_AES_C)
#include "include/iotex/aes.h"
#endif

#if defined(IOTEX_CAMELLIA_C)
#include "include/iotex/camellia.h"
#endif

#if defined(IOTEX_ARIA_C)
#include "include/iotex/aria.h"
#endif

#if defined(IOTEX_DES_C)
#include "include/iotex/des.h"
#endif

#if defined(IOTEX_CHACHA20_C)
#include "include/iotex/chacha20.h"
#endif

#if defined(IOTEX_GCM_C)
#include "include/iotex/gcm.h"
#endif

#if defined(IOTEX_CCM_C)
#include "include/iotex/ccm.h"
#endif

#if defined(IOTEX_NIST_KW_C)
#include "include/iotex/nist_kw.h"
#endif

#if defined(IOTEX_CIPHER_NULL_CIPHER)
#include <string.h>
#endif

#if defined(IOTEX_PLATFORM_C)
#include "include/iotex/platform.h"
#else
#include <stdlib.h>
#define iotex_calloc    calloc
#define iotex_free       free
#endif

#if defined(IOTEX_GCM_C)
/* shared by all GCM ciphers */
static void *gcm_ctx_alloc( void )
{
    void *ctx = iotex_calloc( 1, sizeof( iotex_gcm_context ) );

    if( ctx != NULL )
        iotex_gcm_init( (iotex_gcm_context *) ctx );

    return( ctx );
}

static void gcm_ctx_free( void *ctx )
{
    iotex_gcm_free( ctx );
    iotex_free( ctx );
}
#endif /* IOTEX_GCM_C */

#if defined(IOTEX_CCM_C)
/* shared by all CCM ciphers */
static void *ccm_ctx_alloc( void )
{
    void *ctx = iotex_calloc( 1, sizeof( iotex_ccm_context ) );

    // if( ctx != NULL )
    //     iotex_ccm_init( (iotex_ccm_context *) ctx );

    return( ctx );
}

static void ccm_ctx_free( void *ctx )
{
//    iotex_ccm_free( ctx );
    iotex_free( ctx );
}
#endif /* IOTEX_CCM_C */

#if defined(IOTEX_AES_C)

static int aes_crypt_ecb_wrap( void *ctx, iotex_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    return iotex_aes_crypt_ecb( (iotex_aes_context *) ctx, operation, input, output );
}

#if defined(IOTEX_CIPHER_MODE_CBC)
static int aes_crypt_cbc_wrap( void *ctx, iotex_operation_t operation, size_t length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return iotex_aes_crypt_cbc( (iotex_aes_context *) ctx, operation, length, iv, input,
                          output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
static int aes_crypt_cfb128_wrap( void *ctx, iotex_operation_t operation,
        size_t length, size_t *iv_off, unsigned char *iv,
        const unsigned char *input, unsigned char *output )
{
    return iotex_aes_crypt_cfb128( (iotex_aes_context *) ctx, operation, length, iv_off, iv,
                             input, output );
}
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_OFB)
static int aes_crypt_ofb_wrap( void *ctx, size_t length, size_t *iv_off,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return iotex_aes_crypt_ofb( (iotex_aes_context *) ctx, length, iv_off,
                                    iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_OFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
static int aes_crypt_ctr_wrap( void *ctx, size_t length, size_t *nc_off,
        unsigned char *nonce_counter, unsigned char *stream_block,
        const unsigned char *input, unsigned char *output )
{
    return iotex_aes_crypt_ctr( (iotex_aes_context *) ctx, length, nc_off, nonce_counter,
                          stream_block, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CTR */

#if defined(IOTEX_CIPHER_MODE_XTS)
static int aes_crypt_xts_wrap( void *ctx, iotex_operation_t operation,
                               size_t length,
                               const unsigned char data_unit[16],
                               const unsigned char *input,
                               unsigned char *output )
{
    iotex_aes_xts_context *xts_ctx = ctx;
    int mode;

    switch( operation )
    {
        case IOTEX_ENCRYPT:
            mode = IOTEX_AES_ENCRYPT;
            break;
        case IOTEX_DECRYPT:
            mode = IOTEX_AES_DECRYPT;
            break;
        default:
            return IOTEX_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return iotex_aes_crypt_xts( xts_ctx, mode, length,
                                  data_unit, input, output );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

static int aes_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return iotex_aes_setkey_dec( (iotex_aes_context *) ctx, key, key_bitlen );
}

static int aes_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return iotex_aes_setkey_enc( (iotex_aes_context *) ctx, key, key_bitlen );
}

static void * aes_ctx_alloc( void )
{
    iotex_aes_context *aes = iotex_calloc( 1, sizeof( iotex_aes_context ) );

    if( aes == NULL )
        return( NULL );

    iotex_aes_init( aes );

    return( aes );
}

static void aes_ctx_free( void *ctx )
{
    iotex_aes_free( (iotex_aes_context *) ctx );
    iotex_free( ctx );
}

static const iotex_cipher_base_t aes_info = {
    IOTEX_CIPHER_ID_AES,
    aes_crypt_ecb_wrap,
#if defined(IOTEX_CIPHER_MODE_CBC)
    aes_crypt_cbc_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    aes_crypt_cfb128_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    aes_crypt_ofb_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    aes_crypt_ctr_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    aes_setkey_enc_wrap,
    aes_setkey_dec_wrap,
    aes_ctx_alloc,
    aes_ctx_free
};

static const iotex_cipher_info_t aes_128_ecb_info = {
    IOTEX_CIPHER_AES_128_ECB,
    IOTEX_MODE_ECB,
    128,
    "AES-128-ECB",
    0,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_192_ecb_info = {
    IOTEX_CIPHER_AES_192_ECB,
    IOTEX_MODE_ECB,
    192,
    "AES-192-ECB",
    0,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_256_ecb_info = {
    IOTEX_CIPHER_AES_256_ECB,
    IOTEX_MODE_ECB,
    256,
    "AES-256-ECB",
    0,
    0,
    16,
    &aes_info
};

#if defined(IOTEX_CIPHER_MODE_CBC)
static const iotex_cipher_info_t aes_128_cbc_info = {
    IOTEX_CIPHER_AES_128_CBC,
    IOTEX_MODE_CBC,
    128,
    "AES-128-CBC",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_192_cbc_info = {
    IOTEX_CIPHER_AES_192_CBC,
    IOTEX_MODE_CBC,
    192,
    "AES-192-CBC",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_256_cbc_info = {
    IOTEX_CIPHER_AES_256_CBC,
    IOTEX_MODE_CBC,
    256,
    "AES-256-CBC",
    16,
    0,
    16,
    &aes_info
};
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
static const iotex_cipher_info_t aes_128_cfb128_info = {
    IOTEX_CIPHER_AES_128_CFB128,
    IOTEX_MODE_CFB,
    128,
    "AES-128-CFB128",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_192_cfb128_info = {
    IOTEX_CIPHER_AES_192_CFB128,
    IOTEX_MODE_CFB,
    192,
    "AES-192-CFB128",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_256_cfb128_info = {
    IOTEX_CIPHER_AES_256_CFB128,
    IOTEX_MODE_CFB,
    256,
    "AES-256-CFB128",
    16,
    0,
    16,
    &aes_info
};
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_OFB)
static const iotex_cipher_info_t aes_128_ofb_info = {
    IOTEX_CIPHER_AES_128_OFB,
    IOTEX_MODE_OFB,
    128,
    "AES-128-OFB",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_192_ofb_info = {
    IOTEX_CIPHER_AES_192_OFB,
    IOTEX_MODE_OFB,
    192,
    "AES-192-OFB",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_256_ofb_info = {
    IOTEX_CIPHER_AES_256_OFB,
    IOTEX_MODE_OFB,
    256,
    "AES-256-OFB",
    16,
    0,
    16,
    &aes_info
};
#endif /* IOTEX_CIPHER_MODE_OFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
static const iotex_cipher_info_t aes_128_ctr_info = {
    IOTEX_CIPHER_AES_128_CTR,
    IOTEX_MODE_CTR,
    128,
    "AES-128-CTR",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_192_ctr_info = {
    IOTEX_CIPHER_AES_192_CTR,
    IOTEX_MODE_CTR,
    192,
    "AES-192-CTR",
    16,
    0,
    16,
    &aes_info
};

static const iotex_cipher_info_t aes_256_ctr_info = {
    IOTEX_CIPHER_AES_256_CTR,
    IOTEX_MODE_CTR,
    256,
    "AES-256-CTR",
    16,
    0,
    16,
    &aes_info
};
#endif /* IOTEX_CIPHER_MODE_CTR */

#if defined(IOTEX_CIPHER_MODE_XTS)
static int xts_aes_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen )
{
    iotex_aes_xts_context *xts_ctx = ctx;
    return( iotex_aes_xts_setkey_enc( xts_ctx, key, key_bitlen ) );
}

static int xts_aes_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen )
{
    iotex_aes_xts_context *xts_ctx = ctx;
    return( iotex_aes_xts_setkey_dec( xts_ctx, key, key_bitlen ) );
}

static void *xts_aes_ctx_alloc( void )
{
    iotex_aes_xts_context *xts_ctx = iotex_calloc( 1, sizeof( *xts_ctx ) );

    if( xts_ctx != NULL )
        iotex_aes_xts_init( xts_ctx );

    return( xts_ctx );
}

static void xts_aes_ctx_free( void *ctx )
{
    iotex_aes_xts_context *xts_ctx = ctx;

    if( xts_ctx == NULL )
        return;

    iotex_aes_xts_free( xts_ctx );
    iotex_free( xts_ctx );
}

static const iotex_cipher_base_t xts_aes_info = {
    IOTEX_CIPHER_ID_AES,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    aes_crypt_xts_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    xts_aes_setkey_enc_wrap,
    xts_aes_setkey_dec_wrap,
    xts_aes_ctx_alloc,
    xts_aes_ctx_free
};

static const iotex_cipher_info_t aes_128_xts_info = {
    IOTEX_CIPHER_AES_128_XTS,
    IOTEX_MODE_XTS,
    256,
    "AES-128-XTS",
    16,
    0,
    16,
    &xts_aes_info
};

static const iotex_cipher_info_t aes_256_xts_info = {
    IOTEX_CIPHER_AES_256_XTS,
    IOTEX_MODE_XTS,
    512,
    "AES-256-XTS",
    16,
    0,
    16,
    &xts_aes_info
};
#endif /* IOTEX_CIPHER_MODE_XTS */

#if defined(IOTEX_GCM_C)
static int gcm_aes_setkey_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return iotex_gcm_setkey( (iotex_gcm_context *) ctx, IOTEX_CIPHER_ID_AES,
                     key, key_bitlen );
}

static const iotex_cipher_base_t gcm_aes_info = {
    IOTEX_CIPHER_ID_AES,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    gcm_aes_setkey_wrap,
    gcm_aes_setkey_wrap,
    gcm_ctx_alloc,
    gcm_ctx_free,
};

static const iotex_cipher_info_t aes_128_gcm_info = {
    IOTEX_CIPHER_AES_128_GCM,
    IOTEX_MODE_GCM,
    128,
    "AES-128-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const iotex_cipher_info_t aes_192_gcm_info = {
    IOTEX_CIPHER_AES_192_GCM,
    IOTEX_MODE_GCM,
    192,
    "AES-192-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const iotex_cipher_info_t aes_256_gcm_info = {
    IOTEX_CIPHER_AES_256_GCM,
    IOTEX_MODE_GCM,
    256,
    "AES-256-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};
#endif /* IOTEX_GCM_C */

#if defined(IOTEX_CCM_C)
static int ccm_aes_setkey_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    // return iotex_ccm_setkey( (iotex_ccm_context *) ctx, IOTEX_CIPHER_ID_AES,
    //                  key, key_bitlen );
    return 0;
}

static const iotex_cipher_base_t ccm_aes_info = {
    IOTEX_CIPHER_ID_AES,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    ccm_aes_setkey_wrap,
    ccm_aes_setkey_wrap,
    ccm_ctx_alloc,
    ccm_ctx_free,
};

static const iotex_cipher_info_t aes_128_ccm_info = {
    IOTEX_CIPHER_AES_128_CCM,
    IOTEX_MODE_CCM,
    128,
    "AES-128-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};

static const iotex_cipher_info_t aes_192_ccm_info = {
    IOTEX_CIPHER_AES_192_CCM,
    IOTEX_MODE_CCM,
    192,
    "AES-192-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};

static const iotex_cipher_info_t aes_256_ccm_info = {
    IOTEX_CIPHER_AES_256_CCM,
    IOTEX_MODE_CCM,
    256,
    "AES-256-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};

static const iotex_cipher_info_t aes_128_ccm_star_no_tag_info = {
    IOTEX_CIPHER_AES_128_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    128,
    "AES-128-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};

static const iotex_cipher_info_t aes_192_ccm_star_no_tag_info = {
    IOTEX_CIPHER_AES_192_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    192,
    "AES-192-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};

static const iotex_cipher_info_t aes_256_ccm_star_no_tag_info = {
    IOTEX_CIPHER_AES_256_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    256,
    "AES-256-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};
#endif /* IOTEX_CCM_C */

#endif /* IOTEX_AES_C */

#if defined(IOTEX_CAMELLIA_C)

static int camellia_crypt_ecb_wrap( void *ctx, iotex_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    return iotex_camellia_crypt_ecb( (iotex_camellia_context *) ctx, operation, input,
                               output );
}

#if defined(IOTEX_CIPHER_MODE_CBC)
static int camellia_crypt_cbc_wrap( void *ctx, iotex_operation_t operation,
        size_t length, unsigned char *iv,
        const unsigned char *input, unsigned char *output )
{
    return iotex_camellia_crypt_cbc( (iotex_camellia_context *) ctx, operation, length, iv,
                               input, output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
static int camellia_crypt_cfb128_wrap( void *ctx, iotex_operation_t operation,
        size_t length, size_t *iv_off, unsigned char *iv,
        const unsigned char *input, unsigned char *output )
{
    return iotex_camellia_crypt_cfb128( (iotex_camellia_context *) ctx, operation, length,
                                  iv_off, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
static int camellia_crypt_ctr_wrap( void *ctx, size_t length, size_t *nc_off,
        unsigned char *nonce_counter, unsigned char *stream_block,
        const unsigned char *input, unsigned char *output )
{
    return iotex_camellia_crypt_ctr( (iotex_camellia_context *) ctx, length, nc_off,
                               nonce_counter, stream_block, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CTR */

static int camellia_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_camellia_setkey_dec( (iotex_camellia_context *) ctx, key, key_bitlen );
}

static int camellia_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_camellia_setkey_enc( (iotex_camellia_context *) ctx, key, key_bitlen );
}

static void * camellia_ctx_alloc( void )
{
    iotex_camellia_context *ctx;
    ctx = iotex_calloc( 1, sizeof( iotex_camellia_context ) );

    if( ctx == NULL )
        return( NULL );

    iotex_camellia_init( ctx );

    return( ctx );
}

static void camellia_ctx_free( void *ctx )
{
    iotex_camellia_free( (iotex_camellia_context *) ctx );
    iotex_free( ctx );
}

static const iotex_cipher_base_t camellia_info = {
    IOTEX_CIPHER_ID_CAMELLIA,
    camellia_crypt_ecb_wrap,
#if defined(IOTEX_CIPHER_MODE_CBC)
    camellia_crypt_cbc_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    camellia_crypt_cfb128_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    camellia_crypt_ctr_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    camellia_setkey_enc_wrap,
    camellia_setkey_dec_wrap,
    camellia_ctx_alloc,
    camellia_ctx_free
};

static const iotex_cipher_info_t camellia_128_ecb_info = {
    IOTEX_CIPHER_CAMELLIA_128_ECB,
    IOTEX_MODE_ECB,
    128,
    "CAMELLIA-128-ECB",
    0,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_192_ecb_info = {
    IOTEX_CIPHER_CAMELLIA_192_ECB,
    IOTEX_MODE_ECB,
    192,
    "CAMELLIA-192-ECB",
    0,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_256_ecb_info = {
    IOTEX_CIPHER_CAMELLIA_256_ECB,
    IOTEX_MODE_ECB,
    256,
    "CAMELLIA-256-ECB",
    0,
    0,
    16,
    &camellia_info
};

#if defined(IOTEX_CIPHER_MODE_CBC)
static const iotex_cipher_info_t camellia_128_cbc_info = {
    IOTEX_CIPHER_CAMELLIA_128_CBC,
    IOTEX_MODE_CBC,
    128,
    "CAMELLIA-128-CBC",
    16,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_192_cbc_info = {
    IOTEX_CIPHER_CAMELLIA_192_CBC,
    IOTEX_MODE_CBC,
    192,
    "CAMELLIA-192-CBC",
    16,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_256_cbc_info = {
    IOTEX_CIPHER_CAMELLIA_256_CBC,
    IOTEX_MODE_CBC,
    256,
    "CAMELLIA-256-CBC",
    16,
    0,
    16,
    &camellia_info
};
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
static const iotex_cipher_info_t camellia_128_cfb128_info = {
    IOTEX_CIPHER_CAMELLIA_128_CFB128,
    IOTEX_MODE_CFB,
    128,
    "CAMELLIA-128-CFB128",
    16,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_192_cfb128_info = {
    IOTEX_CIPHER_CAMELLIA_192_CFB128,
    IOTEX_MODE_CFB,
    192,
    "CAMELLIA-192-CFB128",
    16,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_256_cfb128_info = {
    IOTEX_CIPHER_CAMELLIA_256_CFB128,
    IOTEX_MODE_CFB,
    256,
    "CAMELLIA-256-CFB128",
    16,
    0,
    16,
    &camellia_info
};
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
static const iotex_cipher_info_t camellia_128_ctr_info = {
    IOTEX_CIPHER_CAMELLIA_128_CTR,
    IOTEX_MODE_CTR,
    128,
    "CAMELLIA-128-CTR",
    16,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_192_ctr_info = {
    IOTEX_CIPHER_CAMELLIA_192_CTR,
    IOTEX_MODE_CTR,
    192,
    "CAMELLIA-192-CTR",
    16,
    0,
    16,
    &camellia_info
};

static const iotex_cipher_info_t camellia_256_ctr_info = {
    IOTEX_CIPHER_CAMELLIA_256_CTR,
    IOTEX_MODE_CTR,
    256,
    "CAMELLIA-256-CTR",
    16,
    0,
    16,
    &camellia_info
};
#endif /* IOTEX_CIPHER_MODE_CTR */

#if defined(IOTEX_GCM_C)
static int gcm_camellia_setkey_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_gcm_setkey( (iotex_gcm_context *) ctx, IOTEX_CIPHER_ID_CAMELLIA,
                     key, key_bitlen );
}

static const iotex_cipher_base_t gcm_camellia_info = {
    IOTEX_CIPHER_ID_CAMELLIA,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    gcm_camellia_setkey_wrap,
    gcm_camellia_setkey_wrap,
    gcm_ctx_alloc,
    gcm_ctx_free,
};

static const iotex_cipher_info_t camellia_128_gcm_info = {
    IOTEX_CIPHER_CAMELLIA_128_GCM,
    IOTEX_MODE_GCM,
    128,
    "CAMELLIA-128-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_camellia_info
};

static const iotex_cipher_info_t camellia_192_gcm_info = {
    IOTEX_CIPHER_CAMELLIA_192_GCM,
    IOTEX_MODE_GCM,
    192,
    "CAMELLIA-192-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_camellia_info
};

static const iotex_cipher_info_t camellia_256_gcm_info = {
    IOTEX_CIPHER_CAMELLIA_256_GCM,
    IOTEX_MODE_GCM,
    256,
    "CAMELLIA-256-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_camellia_info
};
#endif /* IOTEX_GCM_C */

#if defined(IOTEX_CCM_C)
static int ccm_camellia_setkey_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_ccm_setkey( (iotex_ccm_context *) ctx, IOTEX_CIPHER_ID_CAMELLIA,
                     key, key_bitlen );
}

static const iotex_cipher_base_t ccm_camellia_info = {
    IOTEX_CIPHER_ID_CAMELLIA,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    ccm_camellia_setkey_wrap,
    ccm_camellia_setkey_wrap,
    ccm_ctx_alloc,
    ccm_ctx_free,
};

static const iotex_cipher_info_t camellia_128_ccm_info = {
    IOTEX_CIPHER_CAMELLIA_128_CCM,
    IOTEX_MODE_CCM,
    128,
    "CAMELLIA-128-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_camellia_info
};

static const iotex_cipher_info_t camellia_192_ccm_info = {
    IOTEX_CIPHER_CAMELLIA_192_CCM,
    IOTEX_MODE_CCM,
    192,
    "CAMELLIA-192-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_camellia_info
};

static const iotex_cipher_info_t camellia_256_ccm_info = {
    IOTEX_CIPHER_CAMELLIA_256_CCM,
    IOTEX_MODE_CCM,
    256,
    "CAMELLIA-256-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_camellia_info
};

static const iotex_cipher_info_t camellia_128_ccm_star_no_tag_info = {
    IOTEX_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    128,
    "CAMELLIA-128-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_camellia_info
};

static const iotex_cipher_info_t camellia_192_ccm_star_no_tag_info = {
    IOTEX_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    192,
    "CAMELLIA-192-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_camellia_info
};

static const iotex_cipher_info_t camellia_256_ccm_star_no_tag_info = {
    IOTEX_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    256,
    "CAMELLIA-256-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_camellia_info
};
#endif /* IOTEX_CCM_C */

#endif /* IOTEX_CAMELLIA_C */

#if defined(IOTEX_ARIA_C)

static int aria_crypt_ecb_wrap( void *ctx, iotex_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    (void) operation;
    return iotex_aria_crypt_ecb( (iotex_aria_context *) ctx, input,
                               output );
}

#if defined(IOTEX_CIPHER_MODE_CBC)
static int aria_crypt_cbc_wrap( void *ctx, iotex_operation_t operation,
        size_t length, unsigned char *iv,
        const unsigned char *input, unsigned char *output )
{
    return iotex_aria_crypt_cbc( (iotex_aria_context *) ctx, operation, length, iv,
                               input, output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
static int aria_crypt_cfb128_wrap( void *ctx, iotex_operation_t operation,
        size_t length, size_t *iv_off, unsigned char *iv,
        const unsigned char *input, unsigned char *output )
{
    return iotex_aria_crypt_cfb128( (iotex_aria_context *) ctx, operation, length,
                                  iv_off, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
static int aria_crypt_ctr_wrap( void *ctx, size_t length, size_t *nc_off,
        unsigned char *nonce_counter, unsigned char *stream_block,
        const unsigned char *input, unsigned char *output )
{
    return iotex_aria_crypt_ctr( (iotex_aria_context *) ctx, length, nc_off,
                               nonce_counter, stream_block, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CTR */

static int aria_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_aria_setkey_dec( (iotex_aria_context *) ctx, key, key_bitlen );
}

static int aria_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_aria_setkey_enc( (iotex_aria_context *) ctx, key, key_bitlen );
}

static void * aria_ctx_alloc( void )
{
    iotex_aria_context *ctx;
    ctx = iotex_calloc( 1, sizeof( iotex_aria_context ) );

    if( ctx == NULL )
        return( NULL );

    iotex_aria_init( ctx );

    return( ctx );
}

static void aria_ctx_free( void *ctx )
{
    iotex_aria_free( (iotex_aria_context *) ctx );
    iotex_free( ctx );
}

static const iotex_cipher_base_t aria_info = {
    IOTEX_CIPHER_ID_ARIA,
    aria_crypt_ecb_wrap,
#if defined(IOTEX_CIPHER_MODE_CBC)
    aria_crypt_cbc_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    aria_crypt_cfb128_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    aria_crypt_ctr_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    aria_setkey_enc_wrap,
    aria_setkey_dec_wrap,
    aria_ctx_alloc,
    aria_ctx_free
};

static const iotex_cipher_info_t aria_128_ecb_info = {
    IOTEX_CIPHER_ARIA_128_ECB,
    IOTEX_MODE_ECB,
    128,
    "ARIA-128-ECB",
    0,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_192_ecb_info = {
    IOTEX_CIPHER_ARIA_192_ECB,
    IOTEX_MODE_ECB,
    192,
    "ARIA-192-ECB",
    0,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_256_ecb_info = {
    IOTEX_CIPHER_ARIA_256_ECB,
    IOTEX_MODE_ECB,
    256,
    "ARIA-256-ECB",
    0,
    0,
    16,
    &aria_info
};

#if defined(IOTEX_CIPHER_MODE_CBC)
static const iotex_cipher_info_t aria_128_cbc_info = {
    IOTEX_CIPHER_ARIA_128_CBC,
    IOTEX_MODE_CBC,
    128,
    "ARIA-128-CBC",
    16,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_192_cbc_info = {
    IOTEX_CIPHER_ARIA_192_CBC,
    IOTEX_MODE_CBC,
    192,
    "ARIA-192-CBC",
    16,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_256_cbc_info = {
    IOTEX_CIPHER_ARIA_256_CBC,
    IOTEX_MODE_CBC,
    256,
    "ARIA-256-CBC",
    16,
    0,
    16,
    &aria_info
};
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
static const iotex_cipher_info_t aria_128_cfb128_info = {
    IOTEX_CIPHER_ARIA_128_CFB128,
    IOTEX_MODE_CFB,
    128,
    "ARIA-128-CFB128",
    16,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_192_cfb128_info = {
    IOTEX_CIPHER_ARIA_192_CFB128,
    IOTEX_MODE_CFB,
    192,
    "ARIA-192-CFB128",
    16,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_256_cfb128_info = {
    IOTEX_CIPHER_ARIA_256_CFB128,
    IOTEX_MODE_CFB,
    256,
    "ARIA-256-CFB128",
    16,
    0,
    16,
    &aria_info
};
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
static const iotex_cipher_info_t aria_128_ctr_info = {
    IOTEX_CIPHER_ARIA_128_CTR,
    IOTEX_MODE_CTR,
    128,
    "ARIA-128-CTR",
    16,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_192_ctr_info = {
    IOTEX_CIPHER_ARIA_192_CTR,
    IOTEX_MODE_CTR,
    192,
    "ARIA-192-CTR",
    16,
    0,
    16,
    &aria_info
};

static const iotex_cipher_info_t aria_256_ctr_info = {
    IOTEX_CIPHER_ARIA_256_CTR,
    IOTEX_MODE_CTR,
    256,
    "ARIA-256-CTR",
    16,
    0,
    16,
    &aria_info
};
#endif /* IOTEX_CIPHER_MODE_CTR */

#if defined(IOTEX_GCM_C)
static int gcm_aria_setkey_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_gcm_setkey( (iotex_gcm_context *) ctx, IOTEX_CIPHER_ID_ARIA,
                     key, key_bitlen );
}

static const iotex_cipher_base_t gcm_aria_info = {
    IOTEX_CIPHER_ID_ARIA,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    gcm_aria_setkey_wrap,
    gcm_aria_setkey_wrap,
    gcm_ctx_alloc,
    gcm_ctx_free,
};

static const iotex_cipher_info_t aria_128_gcm_info = {
    IOTEX_CIPHER_ARIA_128_GCM,
    IOTEX_MODE_GCM,
    128,
    "ARIA-128-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aria_info
};

static const iotex_cipher_info_t aria_192_gcm_info = {
    IOTEX_CIPHER_ARIA_192_GCM,
    IOTEX_MODE_GCM,
    192,
    "ARIA-192-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aria_info
};

static const iotex_cipher_info_t aria_256_gcm_info = {
    IOTEX_CIPHER_ARIA_256_GCM,
    IOTEX_MODE_GCM,
    256,
    "ARIA-256-GCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aria_info
};
#endif /* IOTEX_GCM_C */

#if defined(IOTEX_CCM_C)
static int ccm_aria_setkey_wrap( void *ctx, const unsigned char *key,
                                     unsigned int key_bitlen )
{
    return iotex_ccm_setkey( (iotex_ccm_context *) ctx, IOTEX_CIPHER_ID_ARIA,
                     key, key_bitlen );
}

static const iotex_cipher_base_t ccm_aria_info = {
    IOTEX_CIPHER_ID_ARIA,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    ccm_aria_setkey_wrap,
    ccm_aria_setkey_wrap,
    ccm_ctx_alloc,
    ccm_ctx_free,
};

static const iotex_cipher_info_t aria_128_ccm_info = {
    IOTEX_CIPHER_ARIA_128_CCM,
    IOTEX_MODE_CCM,
    128,
    "ARIA-128-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aria_info
};

static const iotex_cipher_info_t aria_192_ccm_info = {
    IOTEX_CIPHER_ARIA_192_CCM,
    IOTEX_MODE_CCM,
    192,
    "ARIA-192-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aria_info
};

static const iotex_cipher_info_t aria_256_ccm_info = {
    IOTEX_CIPHER_ARIA_256_CCM,
    IOTEX_MODE_CCM,
    256,
    "ARIA-256-CCM",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aria_info
};

static const iotex_cipher_info_t aria_128_ccm_star_no_tag_info = {
    IOTEX_CIPHER_ARIA_128_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    128,
    "ARIA-128-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aria_info
};

static const iotex_cipher_info_t aria_192_ccm_star_no_tag_info = {
    IOTEX_CIPHER_ARIA_192_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    192,
    "ARIA-192-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aria_info
};

static const iotex_cipher_info_t aria_256_ccm_star_no_tag_info = {
    IOTEX_CIPHER_ARIA_256_CCM_STAR_NO_TAG,
    IOTEX_MODE_CCM_STAR_NO_TAG,
    256,
    "ARIA-256-CCM*-NO-TAG",
    12,
    IOTEX_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aria_info
};
#endif /* IOTEX_CCM_C */

#endif /* IOTEX_ARIA_C */

#if defined(IOTEX_DES_C)

static int des_crypt_ecb_wrap( void *ctx, iotex_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    ((void) operation);
    return iotex_des_crypt_ecb( (iotex_des_context *) ctx, input, output );
}

static int des3_crypt_ecb_wrap( void *ctx, iotex_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    ((void) operation);
    return iotex_des3_crypt_ecb( (iotex_des3_context *) ctx, input, output );
}

#if defined(IOTEX_CIPHER_MODE_CBC)
static int des_crypt_cbc_wrap( void *ctx, iotex_operation_t operation, size_t length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return iotex_des_crypt_cbc( (iotex_des_context *) ctx, operation, length, iv, input,
                          output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CBC)
static int des3_crypt_cbc_wrap( void *ctx, iotex_operation_t operation, size_t length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return iotex_des3_crypt_cbc( (iotex_des3_context *) ctx, operation, length, iv, input,
                           output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

static int des_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    ((void) key_bitlen);

    return iotex_des_setkey_dec( (iotex_des_context *) ctx, key );
}

static int des_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    ((void) key_bitlen);

    return iotex_des_setkey_enc( (iotex_des_context *) ctx, key );
}

static int des3_set2key_dec_wrap( void *ctx, const unsigned char *key,
                                  unsigned int key_bitlen )
{
    ((void) key_bitlen);

    return iotex_des3_set2key_dec( (iotex_des3_context *) ctx, key );
}

static int des3_set2key_enc_wrap( void *ctx, const unsigned char *key,
                                  unsigned int key_bitlen )
{
    ((void) key_bitlen);

    return iotex_des3_set2key_enc( (iotex_des3_context *) ctx, key );
}

static int des3_set3key_dec_wrap( void *ctx, const unsigned char *key,
                                  unsigned int key_bitlen )
{
    ((void) key_bitlen);

    return iotex_des3_set3key_dec( (iotex_des3_context *) ctx, key );
}

static int des3_set3key_enc_wrap( void *ctx, const unsigned char *key,
                                  unsigned int key_bitlen )
{
    ((void) key_bitlen);

    return iotex_des3_set3key_enc( (iotex_des3_context *) ctx, key );
}

static void * des_ctx_alloc( void )
{
    iotex_des_context *des = iotex_calloc( 1, sizeof( iotex_des_context ) );

    if( des == NULL )
        return( NULL );

    iotex_des_init( des );

    return( des );
}

static void des_ctx_free( void *ctx )
{
    iotex_des_free( (iotex_des_context *) ctx );
    iotex_free( ctx );
}

static void * des3_ctx_alloc( void )
{
    iotex_des3_context *des3;
    des3 = iotex_calloc( 1, sizeof( iotex_des3_context ) );

    if( des3 == NULL )
        return( NULL );

    iotex_des3_init( des3 );

    return( des3 );
}

static void des3_ctx_free( void *ctx )
{
    iotex_des3_free( (iotex_des3_context *) ctx );
    iotex_free( ctx );
}

static const iotex_cipher_base_t des_info = {
    IOTEX_CIPHER_ID_DES,
    des_crypt_ecb_wrap,
#if defined(IOTEX_CIPHER_MODE_CBC)
    des_crypt_cbc_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    des_setkey_enc_wrap,
    des_setkey_dec_wrap,
    des_ctx_alloc,
    des_ctx_free
};

static const iotex_cipher_info_t des_ecb_info = {
    IOTEX_CIPHER_DES_ECB,
    IOTEX_MODE_ECB,
    IOTEX_KEY_LENGTH_DES,
    "DES-ECB",
    0,
    0,
    8,
    &des_info
};

#if defined(IOTEX_CIPHER_MODE_CBC)
static const iotex_cipher_info_t des_cbc_info = {
    IOTEX_CIPHER_DES_CBC,
    IOTEX_MODE_CBC,
    IOTEX_KEY_LENGTH_DES,
    "DES-CBC",
    8,
    0,
    8,
    &des_info
};
#endif /* IOTEX_CIPHER_MODE_CBC */

static const iotex_cipher_base_t des_ede_info = {
    IOTEX_CIPHER_ID_DES,
    des3_crypt_ecb_wrap,
#if defined(IOTEX_CIPHER_MODE_CBC)
    des3_crypt_cbc_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    des3_set2key_enc_wrap,
    des3_set2key_dec_wrap,
    des3_ctx_alloc,
    des3_ctx_free
};

static const iotex_cipher_info_t des_ede_ecb_info = {
    IOTEX_CIPHER_DES_EDE_ECB,
    IOTEX_MODE_ECB,
    IOTEX_KEY_LENGTH_DES_EDE,
    "DES-EDE-ECB",
    0,
    0,
    8,
    &des_ede_info
};

#if defined(IOTEX_CIPHER_MODE_CBC)
static const iotex_cipher_info_t des_ede_cbc_info = {
    IOTEX_CIPHER_DES_EDE_CBC,
    IOTEX_MODE_CBC,
    IOTEX_KEY_LENGTH_DES_EDE,
    "DES-EDE-CBC",
    8,
    0,
    8,
    &des_ede_info
};
#endif /* IOTEX_CIPHER_MODE_CBC */

static const iotex_cipher_base_t des_ede3_info = {
    IOTEX_CIPHER_ID_3DES,
    des3_crypt_ecb_wrap,
#if defined(IOTEX_CIPHER_MODE_CBC)
    des3_crypt_cbc_wrap,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    des3_set3key_enc_wrap,
    des3_set3key_dec_wrap,
    des3_ctx_alloc,
    des3_ctx_free
};

static const iotex_cipher_info_t des_ede3_ecb_info = {
    IOTEX_CIPHER_DES_EDE3_ECB,
    IOTEX_MODE_ECB,
    IOTEX_KEY_LENGTH_DES_EDE3,
    "DES-EDE3-ECB",
    0,
    0,
    8,
    &des_ede3_info
};
#if defined(IOTEX_CIPHER_MODE_CBC)
static const iotex_cipher_info_t des_ede3_cbc_info = {
    IOTEX_CIPHER_DES_EDE3_CBC,
    IOTEX_MODE_CBC,
    IOTEX_KEY_LENGTH_DES_EDE3,
    "DES-EDE3-CBC",
    8,
    0,
    8,
    &des_ede3_info
};
#endif /* IOTEX_CIPHER_MODE_CBC */
#endif /* IOTEX_DES_C */

#if defined(IOTEX_CHACHA20_C)

static int chacha20_setkey_wrap( void *ctx, const unsigned char *key,
                                 unsigned int key_bitlen )
{
    if( key_bitlen != 256U )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if ( 0 != iotex_chacha20_setkey( (iotex_chacha20_context*)ctx, key ) )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    return( 0 );
}

static int chacha20_stream_wrap( void *ctx,  size_t length,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;

    ret = iotex_chacha20_update( ctx, length, input, output );
    if( ret == IOTEX_ERR_CHACHA20_BAD_INPUT_DATA )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    return( ret );
}

static void * chacha20_ctx_alloc( void )
{
    iotex_chacha20_context *ctx;
    ctx = iotex_calloc( 1, sizeof( iotex_chacha20_context ) );

    if( ctx == NULL )
        return( NULL );

    iotex_chacha20_init( ctx );

    return( ctx );
}

static void chacha20_ctx_free( void *ctx )
{
    iotex_chacha20_free( (iotex_chacha20_context *) ctx );
    iotex_free( ctx );
}

static const iotex_cipher_base_t chacha20_base_info = {
    IOTEX_CIPHER_ID_CHACHA20,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    chacha20_stream_wrap,
#endif
    chacha20_setkey_wrap,
    chacha20_setkey_wrap,
    chacha20_ctx_alloc,
    chacha20_ctx_free
};
static const iotex_cipher_info_t chacha20_info = {
    IOTEX_CIPHER_CHACHA20,
    IOTEX_MODE_STREAM,
    256,
    "CHACHA20",
    12,
    0,
    1,
    &chacha20_base_info
};
#endif /* IOTEX_CHACHA20_C */

#if defined(IOTEX_CHACHAPOLY_C)

static int chachapoly_setkey_wrap( void *ctx,
                                   const unsigned char *key,
                                   unsigned int key_bitlen )
{
    if( key_bitlen != 256U )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if ( 0 != iotex_chachapoly_setkey( (iotex_chachapoly_context*)ctx, key ) )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    return( 0 );
}

static void * chachapoly_ctx_alloc( void )
{
    iotex_chachapoly_context *ctx;
    ctx = iotex_calloc( 1, sizeof( iotex_chachapoly_context ) );

    if( ctx == NULL )
        return( NULL );

    iotex_chachapoly_init( ctx );

    return( ctx );
}

static void chachapoly_ctx_free( void *ctx )
{
    iotex_chachapoly_free( (iotex_chachapoly_context *) ctx );
    iotex_free( ctx );
}

static const iotex_cipher_base_t chachapoly_base_info = {
    IOTEX_CIPHER_ID_CHACHA20,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    chachapoly_setkey_wrap,
    chachapoly_setkey_wrap,
    chachapoly_ctx_alloc,
    chachapoly_ctx_free
};
static const iotex_cipher_info_t chachapoly_info = {
    IOTEX_CIPHER_CHACHA20_POLY1305,
    IOTEX_MODE_CHACHAPOLY,
    256,
    "CHACHA20-POLY1305",
    12,
    0,
    1,
    &chachapoly_base_info
};
#endif /* IOTEX_CHACHAPOLY_C */

#if defined(IOTEX_CIPHER_NULL_CIPHER)
static int null_crypt_stream( void *ctx, size_t length,
                              const unsigned char *input,
                              unsigned char *output )
{
    ((void) ctx);
    memmove( output, input, length );
    return( 0 );
}

static int null_setkey( void *ctx, const unsigned char *key,
                        unsigned int key_bitlen )
{
    ((void) ctx);
    ((void) key);
    ((void) key_bitlen);

    return( 0 );
}

static void * null_ctx_alloc( void )
{
    return( (void *) 1 );
}

static void null_ctx_free( void *ctx )
{
    ((void) ctx);
}

static const iotex_cipher_base_t null_base_info = {
    IOTEX_CIPHER_ID_NULL,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    null_crypt_stream,
#endif
    null_setkey,
    null_setkey,
    null_ctx_alloc,
    null_ctx_free
};

static const iotex_cipher_info_t null_cipher_info = {
    IOTEX_CIPHER_NULL,
    IOTEX_MODE_STREAM,
    0,
    "NULL",
    0,
    0,
    1,
    &null_base_info
};
#endif /* defined(IOTEX_CIPHER_NULL_CIPHER) */

#if defined(IOTEX_NIST_KW_C)
static void *kw_ctx_alloc( void )
{
    void *ctx = iotex_calloc( 1, sizeof( iotex_nist_kw_context ) );

    if( ctx != NULL )
        iotex_nist_kw_init( (iotex_nist_kw_context *) ctx );

    return( ctx );
}

static void kw_ctx_free( void *ctx )
{
    iotex_nist_kw_free( ctx );
    iotex_free( ctx );
}

static int kw_aes_setkey_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return iotex_nist_kw_setkey( (iotex_nist_kw_context *) ctx,
                                   IOTEX_CIPHER_ID_AES, key, key_bitlen, 1 );
}

static int kw_aes_setkey_unwrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
   return iotex_nist_kw_setkey( (iotex_nist_kw_context *) ctx,
                                  IOTEX_CIPHER_ID_AES, key, key_bitlen, 0 );
}

static const iotex_cipher_base_t kw_aes_info = {
    IOTEX_CIPHER_ID_AES,
    NULL,
#if defined(IOTEX_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(IOTEX_CIPHER_MODE_STREAM)
    NULL,
#endif
    kw_aes_setkey_wrap,
    kw_aes_setkey_unwrap,
    kw_ctx_alloc,
    kw_ctx_free,
};

static const iotex_cipher_info_t aes_128_nist_kw_info = {
    IOTEX_CIPHER_AES_128_KW,
    IOTEX_MODE_KW,
    128,
    "AES-128-KW",
    0,
    0,
    16,
    &kw_aes_info
};

static const iotex_cipher_info_t aes_192_nist_kw_info = {
    IOTEX_CIPHER_AES_192_KW,
    IOTEX_MODE_KW,
    192,
    "AES-192-KW",
    0,
    0,
    16,
    &kw_aes_info
};

static const iotex_cipher_info_t aes_256_nist_kw_info = {
    IOTEX_CIPHER_AES_256_KW,
    IOTEX_MODE_KW,
    256,
    "AES-256-KW",
    0,
    0,
    16,
    &kw_aes_info
};

static const iotex_cipher_info_t aes_128_nist_kwp_info = {
    IOTEX_CIPHER_AES_128_KWP,
    IOTEX_MODE_KWP,
    128,
    "AES-128-KWP",
    0,
    0,
    16,
    &kw_aes_info
};

static const iotex_cipher_info_t aes_192_nist_kwp_info = {
    IOTEX_CIPHER_AES_192_KWP,
    IOTEX_MODE_KWP,
    192,
    "AES-192-KWP",
    0,
    0,
    16,
    &kw_aes_info
};

static const iotex_cipher_info_t aes_256_nist_kwp_info = {
    IOTEX_CIPHER_AES_256_KWP,
    IOTEX_MODE_KWP,
    256,
    "AES-256-KWP",
    0,
    0,
    16,
    &kw_aes_info
};
#endif /* IOTEX_NIST_KW_C */

const iotex_cipher_definition_t iotex_cipher_definitions[] =
{
#if defined(IOTEX_AES_C)
    { IOTEX_CIPHER_AES_128_ECB,          &aes_128_ecb_info },
    { IOTEX_CIPHER_AES_192_ECB,          &aes_192_ecb_info },
    { IOTEX_CIPHER_AES_256_ECB,          &aes_256_ecb_info },
#if defined(IOTEX_CIPHER_MODE_CBC)
    { IOTEX_CIPHER_AES_128_CBC,          &aes_128_cbc_info },
    { IOTEX_CIPHER_AES_192_CBC,          &aes_192_cbc_info },
    { IOTEX_CIPHER_AES_256_CBC,          &aes_256_cbc_info },
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    { IOTEX_CIPHER_AES_128_CFB128,       &aes_128_cfb128_info },
    { IOTEX_CIPHER_AES_192_CFB128,       &aes_192_cfb128_info },
    { IOTEX_CIPHER_AES_256_CFB128,       &aes_256_cfb128_info },
#endif
#if defined(IOTEX_CIPHER_MODE_OFB)
    { IOTEX_CIPHER_AES_128_OFB,          &aes_128_ofb_info },
    { IOTEX_CIPHER_AES_192_OFB,          &aes_192_ofb_info },
    { IOTEX_CIPHER_AES_256_OFB,          &aes_256_ofb_info },
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    { IOTEX_CIPHER_AES_128_CTR,          &aes_128_ctr_info },
    { IOTEX_CIPHER_AES_192_CTR,          &aes_192_ctr_info },
    { IOTEX_CIPHER_AES_256_CTR,          &aes_256_ctr_info },
#endif
#if defined(IOTEX_CIPHER_MODE_XTS)
    { IOTEX_CIPHER_AES_128_XTS,          &aes_128_xts_info },
    { IOTEX_CIPHER_AES_256_XTS,          &aes_256_xts_info },
#endif
#if defined(IOTEX_GCM_C)
    { IOTEX_CIPHER_AES_128_GCM,          &aes_128_gcm_info },
    { IOTEX_CIPHER_AES_192_GCM,          &aes_192_gcm_info },
    { IOTEX_CIPHER_AES_256_GCM,          &aes_256_gcm_info },
#endif
#if defined(IOTEX_CCM_C)
    { IOTEX_CIPHER_AES_128_CCM,          &aes_128_ccm_info },
    { IOTEX_CIPHER_AES_192_CCM,          &aes_192_ccm_info },
    { IOTEX_CIPHER_AES_256_CCM,          &aes_256_ccm_info },
    { IOTEX_CIPHER_AES_128_CCM_STAR_NO_TAG,          &aes_128_ccm_star_no_tag_info },
    { IOTEX_CIPHER_AES_192_CCM_STAR_NO_TAG,          &aes_192_ccm_star_no_tag_info },
    { IOTEX_CIPHER_AES_256_CCM_STAR_NO_TAG,          &aes_256_ccm_star_no_tag_info },
#endif
#endif /* IOTEX_AES_C */

#if defined(IOTEX_CAMELLIA_C)
    { IOTEX_CIPHER_CAMELLIA_128_ECB,     &camellia_128_ecb_info },
    { IOTEX_CIPHER_CAMELLIA_192_ECB,     &camellia_192_ecb_info },
    { IOTEX_CIPHER_CAMELLIA_256_ECB,     &camellia_256_ecb_info },
#if defined(IOTEX_CIPHER_MODE_CBC)
    { IOTEX_CIPHER_CAMELLIA_128_CBC,     &camellia_128_cbc_info },
    { IOTEX_CIPHER_CAMELLIA_192_CBC,     &camellia_192_cbc_info },
    { IOTEX_CIPHER_CAMELLIA_256_CBC,     &camellia_256_cbc_info },
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    { IOTEX_CIPHER_CAMELLIA_128_CFB128,  &camellia_128_cfb128_info },
    { IOTEX_CIPHER_CAMELLIA_192_CFB128,  &camellia_192_cfb128_info },
    { IOTEX_CIPHER_CAMELLIA_256_CFB128,  &camellia_256_cfb128_info },
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    { IOTEX_CIPHER_CAMELLIA_128_CTR,     &camellia_128_ctr_info },
    { IOTEX_CIPHER_CAMELLIA_192_CTR,     &camellia_192_ctr_info },
    { IOTEX_CIPHER_CAMELLIA_256_CTR,     &camellia_256_ctr_info },
#endif
#if defined(IOTEX_GCM_C)
    { IOTEX_CIPHER_CAMELLIA_128_GCM,     &camellia_128_gcm_info },
    { IOTEX_CIPHER_CAMELLIA_192_GCM,     &camellia_192_gcm_info },
    { IOTEX_CIPHER_CAMELLIA_256_GCM,     &camellia_256_gcm_info },
#endif
#if defined(IOTEX_CCM_C)
    { IOTEX_CIPHER_CAMELLIA_128_CCM,     &camellia_128_ccm_info },
    { IOTEX_CIPHER_CAMELLIA_192_CCM,     &camellia_192_ccm_info },
    { IOTEX_CIPHER_CAMELLIA_256_CCM,     &camellia_256_ccm_info },
    { IOTEX_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG,     &camellia_128_ccm_star_no_tag_info },
    { IOTEX_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG,     &camellia_192_ccm_star_no_tag_info },
    { IOTEX_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG,     &camellia_256_ccm_star_no_tag_info },
#endif
#endif /* IOTEX_CAMELLIA_C */

#if defined(IOTEX_ARIA_C)
    { IOTEX_CIPHER_ARIA_128_ECB,     &aria_128_ecb_info },
    { IOTEX_CIPHER_ARIA_192_ECB,     &aria_192_ecb_info },
    { IOTEX_CIPHER_ARIA_256_ECB,     &aria_256_ecb_info },
#if defined(IOTEX_CIPHER_MODE_CBC)
    { IOTEX_CIPHER_ARIA_128_CBC,     &aria_128_cbc_info },
    { IOTEX_CIPHER_ARIA_192_CBC,     &aria_192_cbc_info },
    { IOTEX_CIPHER_ARIA_256_CBC,     &aria_256_cbc_info },
#endif
#if defined(IOTEX_CIPHER_MODE_CFB)
    { IOTEX_CIPHER_ARIA_128_CFB128,  &aria_128_cfb128_info },
    { IOTEX_CIPHER_ARIA_192_CFB128,  &aria_192_cfb128_info },
    { IOTEX_CIPHER_ARIA_256_CFB128,  &aria_256_cfb128_info },
#endif
#if defined(IOTEX_CIPHER_MODE_CTR)
    { IOTEX_CIPHER_ARIA_128_CTR,     &aria_128_ctr_info },
    { IOTEX_CIPHER_ARIA_192_CTR,     &aria_192_ctr_info },
    { IOTEX_CIPHER_ARIA_256_CTR,     &aria_256_ctr_info },
#endif
#if defined(IOTEX_GCM_C)
    { IOTEX_CIPHER_ARIA_128_GCM,     &aria_128_gcm_info },
    { IOTEX_CIPHER_ARIA_192_GCM,     &aria_192_gcm_info },
    { IOTEX_CIPHER_ARIA_256_GCM,     &aria_256_gcm_info },
#endif
#if defined(IOTEX_CCM_C)
    { IOTEX_CIPHER_ARIA_128_CCM,     &aria_128_ccm_info },
    { IOTEX_CIPHER_ARIA_192_CCM,     &aria_192_ccm_info },
    { IOTEX_CIPHER_ARIA_256_CCM,     &aria_256_ccm_info },
    { IOTEX_CIPHER_ARIA_128_CCM_STAR_NO_TAG,     &aria_128_ccm_star_no_tag_info },
    { IOTEX_CIPHER_ARIA_192_CCM_STAR_NO_TAG,     &aria_192_ccm_star_no_tag_info },
    { IOTEX_CIPHER_ARIA_256_CCM_STAR_NO_TAG,     &aria_256_ccm_star_no_tag_info },
#endif
#endif /* IOTEX_ARIA_C */

#if defined(IOTEX_DES_C)
    { IOTEX_CIPHER_DES_ECB,              &des_ecb_info },
    { IOTEX_CIPHER_DES_EDE_ECB,          &des_ede_ecb_info },
    { IOTEX_CIPHER_DES_EDE3_ECB,         &des_ede3_ecb_info },
#if defined(IOTEX_CIPHER_MODE_CBC)
    { IOTEX_CIPHER_DES_CBC,              &des_cbc_info },
    { IOTEX_CIPHER_DES_EDE_CBC,          &des_ede_cbc_info },
    { IOTEX_CIPHER_DES_EDE3_CBC,         &des_ede3_cbc_info },
#endif
#endif /* IOTEX_DES_C */

#if defined(IOTEX_CHACHA20_C)
    { IOTEX_CIPHER_CHACHA20,             &chacha20_info },
#endif

#if defined(IOTEX_CHACHAPOLY_C)
    { IOTEX_CIPHER_CHACHA20_POLY1305,    &chachapoly_info },
#endif

#if defined(IOTEX_NIST_KW_C)
    { IOTEX_CIPHER_AES_128_KW,          &aes_128_nist_kw_info },
    { IOTEX_CIPHER_AES_192_KW,          &aes_192_nist_kw_info },
    { IOTEX_CIPHER_AES_256_KW,          &aes_256_nist_kw_info },
    { IOTEX_CIPHER_AES_128_KWP,         &aes_128_nist_kwp_info },
    { IOTEX_CIPHER_AES_192_KWP,         &aes_192_nist_kwp_info },
    { IOTEX_CIPHER_AES_256_KWP,         &aes_256_nist_kwp_info },
#endif

#if defined(IOTEX_CIPHER_NULL_CIPHER)
    { IOTEX_CIPHER_NULL,                 &null_cipher_info },
#endif /* IOTEX_CIPHER_NULL_CIPHER */

    { IOTEX_CIPHER_NONE, NULL }
};

#define NUM_CIPHERS ( sizeof(iotex_cipher_definitions) /      \
                      sizeof(iotex_cipher_definitions[0]) )
int iotex_cipher_supported[NUM_CIPHERS];

#endif /* IOTEX_CIPHER_C */
