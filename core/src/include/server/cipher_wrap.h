/**
 * \file cipher_wrap.h
 *
 * \brief Cipher wrappers.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
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
#ifndef IOTEX_CIPHER_WRAP_H
#define IOTEX_CIPHER_WRAP_H

#include "include/iotex/build_info.h"

#include "include/iotex/cipher.h"

#if defined(IOTEX_USE_PSA_CRYPTO)
#include "include/server/crypto.h"
#endif /* IOTEX_USE_PSA_CRYPTO */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Base cipher information. The non-mode specific functions and values.
 */
struct iotex_cipher_base_t
{
    /** Base Cipher type (e.g. IOTEX_CIPHER_ID_AES) */
    iotex_cipher_id_t cipher;

    /** Encrypt using ECB */
    int (*ecb_func)( void *ctx, iotex_operation_t mode,
                     const unsigned char *input, unsigned char *output );

#if defined(IOTEX_CIPHER_MODE_CBC)
    /** Encrypt using CBC */
    int (*cbc_func)( void *ctx, iotex_operation_t mode, size_t length,
                     unsigned char *iv, const unsigned char *input,
                     unsigned char *output );
#endif

#if defined(IOTEX_CIPHER_MODE_CFB)
    /** Encrypt using CFB (Full length) */
    int (*cfb_func)( void *ctx, iotex_operation_t mode, size_t length, size_t *iv_off,
                     unsigned char *iv, const unsigned char *input,
                     unsigned char *output );
#endif

#if defined(IOTEX_CIPHER_MODE_OFB)
    /** Encrypt using OFB (Full length) */
    int (*ofb_func)( void *ctx, size_t length, size_t *iv_off,
                     unsigned char *iv,
                     const unsigned char *input,
                     unsigned char *output );
#endif

#if defined(IOTEX_CIPHER_MODE_CTR)
    /** Encrypt using CTR */
    int (*ctr_func)( void *ctx, size_t length, size_t *nc_off,
                     unsigned char *nonce_counter, unsigned char *stream_block,
                     const unsigned char *input, unsigned char *output );
#endif

#if defined(IOTEX_CIPHER_MODE_XTS)
    /** Encrypt or decrypt using XTS. */
    int (*xts_func)( void *ctx, iotex_operation_t mode, size_t length,
                     const unsigned char data_unit[16],
                     const unsigned char *input, unsigned char *output );
#endif

#if defined(IOTEX_CIPHER_MODE_STREAM)
    /** Encrypt using STREAM */
    int (*stream_func)( void *ctx, size_t length,
                        const unsigned char *input, unsigned char *output );
#endif

    /** Set key for encryption purposes */
    int (*setkey_enc_func)( void *ctx, const unsigned char *key,
                            unsigned int key_bitlen );

    /** Set key for decryption purposes */
    int (*setkey_dec_func)( void *ctx, const unsigned char *key,
                            unsigned int key_bitlen);

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

};

typedef struct
{
    iotex_cipher_type_t type;
    const iotex_cipher_info_t *info;
} iotex_cipher_definition_t;

#if defined(IOTEX_USE_PSA_CRYPTO)
typedef enum
{
    IOTEX_CIPHER_PSA_KEY_UNSET = 0,
    IOTEX_CIPHER_PSA_KEY_OWNED, /* Used for PSA-based cipher contexts which */
                                  /* use raw key material internally imported */
                                  /* as a volatile key, and which hence need  */
                                  /* to destroy that key when the context is  */
                                  /* freed.                                   */
    IOTEX_CIPHER_PSA_KEY_NOT_OWNED, /* Used for PSA-based cipher contexts   */
                                      /* which use a key provided by the      */
                                      /* user, and which hence will not be    */
                                      /* destroyed when the context is freed. */
} iotex_cipher_psa_key_ownership;

typedef struct
{
    psa_algorithm_t alg;
    iotex_svc_key_id_t slot;
    iotex_cipher_psa_key_ownership slot_state;
} iotex_cipher_context_psa;
#endif /* IOTEX_USE_PSA_CRYPTO */

extern const iotex_cipher_definition_t iotex_cipher_definitions[];

extern int iotex_cipher_supported[];

#ifdef __cplusplus
}
#endif

#endif /* IOTEX_CIPHER_WRAP_H */
