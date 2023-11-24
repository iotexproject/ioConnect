#ifndef IOTEX_PK_WRAP_H
#define IOTEX_PK_WRAP_H

#include "include/iotex/build_info.h"

#include "include/iotex/pk.h"

#if defined(IOTEX_PSA_CRYPTO_C)
#include "include/server/crypto.h"
#endif /* IOTEX_PSA_CRYPTO_C */

struct iotex_pk_info_t
{
    /** Public key type */
    iotex_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_bitlen)( const void * );

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)( iotex_pk_type_t type );

    /** Verify signature */
    int (*verify_func)( void *ctx, iotex_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len );

    /** Make signature */
    int (*sign_func)( void *ctx, iotex_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t sig_size, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

#if defined(IOTEX_ECDSA_C) && defined(IOTEX_ECP_RESTARTABLE)
    /** Verify signature (restartable) */
    int (*verify_rs_func)( void *ctx, iotex_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len,
                           void *rs_ctx );

    /** Make signature (restartable) */
    int (*sign_rs_func)( void *ctx, iotex_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng, void *rs_ctx );
#endif /* IOTEX_ECDSA_C && IOTEX_ECP_RESTARTABLE */

    /** Decrypt message */
    int (*decrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Encrypt message */
    int (*encrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Check public-private key pair */
    int (*check_pair_func)( const void *pub, const void *prv,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

#if defined(IOTEX_ECDSA_C) && defined(IOTEX_ECP_RESTARTABLE)
    /** Allocate the restart context */
    void * (*rs_alloc_func)( void );

    /** Free the restart context */
    void (*rs_free_func)( void *rs_ctx );
#endif /* IOTEX_ECDSA_C && IOTEX_ECP_RESTARTABLE */

    /** Interface with the debug module */
    void (*debug_func)( const void *ctx, iotex_pk_debug_item *items );

};
#if defined(IOTEX_PK_RSA_ALT_SUPPORT)
/* Container for RSA-alt */
typedef struct
{
    void *key;
    iotex_pk_rsa_alt_decrypt_func decrypt_func;
    iotex_pk_rsa_alt_sign_func sign_func;
    iotex_pk_rsa_alt_key_len_func key_len_func;
} iotex_rsa_alt_context;
#endif

#if defined(IOTEX_RSA_C)
extern const iotex_pk_info_t iotex_rsa_info;
#endif

#if defined(IOTEX_ECP_C)
extern const iotex_pk_info_t iotex_eckey_info;
extern const iotex_pk_info_t iotex_eckeydh_info;
#endif

#if defined(IOTEX_ECDSA_C)
extern const iotex_pk_info_t iotex_ecdsa_info;
#endif

#if defined(IOTEX_PK_RSA_ALT_SUPPORT)
extern const iotex_pk_info_t iotex_rsa_alt_info;
#endif

#if defined(IOTEX_USE_PSA_CRYPTO)
extern const iotex_pk_info_t iotex_pk_ecdsa_opaque_info;
extern const iotex_pk_info_t iotex_pk_rsa_opaque_info;

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
int iotex_pk_error_from_psa_ecdsa( psa_status_t status );
#endif

#endif /* IOTEX_USE_PSA_CRYPTO */

#if defined(IOTEX_PSA_CRYPTO_C)
int iotex_pk_error_from_psa( psa_status_t status );

#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) ||    \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
int iotex_pk_error_from_psa_rsa( psa_status_t status );
#endif /* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY || PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */

#if defined(IOTEX_RSA_C)
int  iotex_pk_psa_rsa_sign_ext( psa_algorithm_t psa_alg_md,
                                  iotex_rsa_context *rsa_ctx,
                                  const unsigned char *hash, size_t hash_len,
                                  unsigned char *sig, size_t sig_size,
                                  size_t *sig_len );
#endif /* IOTEX_RSA_C */

#endif /* IOTEX_PSA_CRYPTO_C */

#endif /* IOTEX_PK_WRAP_H */
