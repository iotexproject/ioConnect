#include "include/common.h"

#include "include/iotex/platform.h"

#if defined(IOTEX_PSA_CRYPTO_C)
#if defined(CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT)

#if defined(IOTEX_PSA_CRYPTO_CONFIG)
#include "include/check_crypto_config.h"
#endif

#include "include/server/crypto.h"
#include "include/server/crypto_values.h"

#include "include/server/crypto/psa_crypto_all.h"
#include "include/iotex/iotex_crypto_all.h"

#include "include/server/crypto/psa_crypto_random_impl.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "include/iotex/platform.h"
#if !defined(IOTEX_PLATFORM_C)
#define iotex_calloc calloc
#define iotex_free   free
#endif

#include "include/server/cipher_wrap.h"

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_IOTEX
#include "include/iotex/aes.h"
#include "include/iotex/asn1.h"
#include "include/iotex/asn1write.h"
#include "include/iotex/bignum.h"
#include "include/iotex/camellia.h"
#include "include/iotex/chacha20.h"
#include "include/iotex/chachapoly.h"
#include "include/iotex/cipher.h"
#include "include/iotex/ccm.h"
#include "include/iotex/cmac.h"
#include "include/iotex/des.h"
#include "include/iotex/ecdh.h"
#include "include/iotex/ecp.h"
#include "include/iotex/entropy.h"
#include "include/iotex/error.h"
#include "include/iotex/gcm.h"
#include "include/iotex/md5.h"
#include "include/iotex/md.h"
//#include "include/md_wrap.h"
#include "include/iotex/pk.h"
//#include "include/pk_wrap.h"
#include "include/iotex/platform_util.h"
#include "include/iotex/error.h"
#include "include/iotex/ripemd160.h"
#include "include/iotex/rsa.h"
#include "include/iotex/sha1.h"
#include "include/iotex/sha256.h"
#include "include/iotex/sha512.h"
#endif

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT

#include "include/backends/tinycryt/constants.h"
#include "include/backends/tinycryt/sha256.h"
#include "include/backends/tinycryt/sha512.h"
#include "include/backends/tinycryt/ecc.h"
#include "include/backends/tinycryt/ecc_dh.h"
#include "include/backends/tinycryt/ecc_dsa.h"
#include "include/backends/tinycryt/ed_dsa.h"
#include "include/backends/tinycryt/ecc_platform_specific.h"
#include "include/backends/tinycryt/aes.h"
#include "include/backends/tinycryt/hmac_prng.h"
#include "include/backends/tinycryt/hmac.h"
#include "include/backends/tinycryt/ctr_mode.h"
#include "include/backends/tinycryt/ccm_mode.h"

#endif

/****************************************************************/
/* To prevent link errors */
/****************************************************************/
int iotex_ccm_update_ad( iotex_ccm_context *ctx,
                           const unsigned char *ad,
                           size_t ad_len )
{
    return 0;
}

int iotex_ccm_finish( iotex_ccm_context *ctx,
                        unsigned char *tag, size_t tag_len )
{
    return 0;
}

psa_status_t iotex_psa_mac_verify_finish(
    iotex_psa_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    return 0;
}

psa_status_t iotex_psa_mac_abort(
    iotex_psa_mac_operation_t *operation )
{
    return PSA_SUCCESS;
}

void iotex_ecp_group_init( iotex_ecp_group *grp )
{

}

int iotex_mpi_sub_int( iotex_mpi *X, const iotex_mpi *A,
                         iotex_mpi_sint b )
{
    return 0;
}

int iotex_mpi_lt_mpi_ct( const iotex_mpi *X, const iotex_mpi *Y,
        unsigned *ret )
{
    return 0;
}

int iotex_mpi_add_int( iotex_mpi *X, const iotex_mpi *A,
                         iotex_mpi_sint b )
{
    return 0;
}

int iotex_ecdh_get_params( iotex_ecdh_context *ctx,
                             const iotex_ecp_keypair *key,
                             iotex_ecdh_side side )
{
    return 0;
}

int iotex_ecdh_calc_secret( iotex_ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    return 0;
}

void iotex_ecdh_free( iotex_ecdh_context *ctx )
{

}

void iotex_ecdh_init( iotex_ecdh_context *ctx )
{
    
}

/****************************************************************/
/* Global data, support functions and library management */
/****************************************************************/
#define ECP_VALIDATE_RET( cond )    \
    IOTEX_INTERNAL_VALIDATE_RET( cond, IOTEX_ERR_ECP_BAD_INPUT_DATA )
#define ECP_VALIDATE( cond )        \
    IOTEX_INTERNAL_VALIDATE( cond )

#define ECP_CURVE25519_KEY_SIZE 32
#define ECP_CURVE448_KEY_SIZE   56

static struct tc_aes_key_sched_struct s;
static struct tc_ccm_mode_struct c;
static struct tc_hmac_state_struct hmac_ctx;

/****************************************************************/
/* Static */
/****************************************************************/
#if defined(IOTEX_CIPHER_MODE_WITH_PADDING)
#if defined(IOTEX_CIPHER_PADDING_PKCS7)
/*
 * PKCS7 (and PKCS5) padding: fill with ll bytes, with ll = padding_len
 */
static void add_pkcs_padding( unsigned char *output, size_t output_len,
        size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i;

    for( i = 0; i < padding_len; i++ )
        output[data_len + i] = (unsigned char) padding_len;
}

static int get_pkcs_padding( unsigned char *input, size_t input_len,
        size_t *data_len )
{
    size_t i, pad_idx;
    unsigned char padding_len, bad = 0;

    if( NULL == input || NULL == data_len )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    if (( padding_len >= input_len ) || ( padding_len == 0 ))
    {
        *data_len = input_len;
        return 0;
    }

    /* Avoid logical || since it results in a branch */
    bad |= padding_len > input_len;
    bad |= padding_len == 0;

    /* The number of bytes checked must be independent of padding_len,
     * so pick input_len, which is usually 8 or 16 (one block) */
    pad_idx = input_len - padding_len;
    for( i = 0; i < input_len; i++ )
    {        
        bad |= ( input[i] ^ padding_len ) * ( i >= pad_idx );
    }

    return( IOTEX_ERR_CIPHER_INVALID_PADDING * ( bad != 0 ) );
}
#endif /* IOTEX_CIPHER_PADDING_PKCS7 */

#if defined(IOTEX_CIPHER_PADDING_ONE_AND_ZEROS)
/*
 * One and zeros padding: fill with 80 00 ... 00
 */
static void add_one_and_zeros_padding( unsigned char *output,
                                       size_t output_len, size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    output[data_len] = 0x80;
    for( i = 1; i < padding_len; i++ )
        output[data_len + i] = 0x00;
}

static int get_one_and_zeros_padding( unsigned char *input, size_t input_len,
                                      size_t *data_len )
{
    size_t i;
    unsigned char done = 0, prev_done, bad;

    if( NULL == input || NULL == data_len )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    bad = 0x80;
    *data_len = 0;
    for( i = input_len; i > 0; i-- )
    {
        prev_done = done;
        done |= ( input[i - 1] != 0 );
        *data_len |= ( i - 1 ) * ( done != prev_done );
        bad ^= input[i - 1] * ( done != prev_done );
    }

    return( IOTEX_ERR_CIPHER_INVALID_PADDING * ( bad != 0 ) );

}
#endif /* IOTEX_CIPHER_PADDING_ONE_AND_ZEROS */

#if defined(IOTEX_CIPHER_PADDING_ZEROS_AND_LEN)
/*
 * Zeros and len padding: fill with 00 ... 00 ll, where ll is padding length
 */
static void add_zeros_and_len_padding( unsigned char *output,
                                       size_t output_len, size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    for( i = 1; i < padding_len; i++ )
        output[data_len + i - 1] = 0x00;
    output[output_len - 1] = (unsigned char) padding_len;
}

static int get_zeros_and_len_padding( unsigned char *input, size_t input_len,
                                      size_t *data_len )
{
    size_t i, pad_idx;
    unsigned char padding_len, bad = 0;

    if( NULL == input || NULL == data_len )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    /* Avoid logical || since it results in a branch */
    bad |= padding_len > input_len;
    bad |= padding_len == 0;

    /* The number of bytes checked must be independent of padding_len */
    pad_idx = input_len - padding_len;
    for( i = 0; i < input_len - 1; i++ )
        bad |= input[i] * ( i >= pad_idx );

    return( IOTEX_ERR_CIPHER_INVALID_PADDING * ( bad != 0 ) );
}
#endif /* IOTEX_CIPHER_PADDING_ZEROS_AND_LEN */

#if defined(IOTEX_CIPHER_PADDING_ZEROS)
/*
 * Zero padding: fill with 00 ... 00
 */
static void add_zeros_padding( unsigned char *output,
                               size_t output_len, size_t data_len )
{
    size_t i;

    for( i = data_len; i < output_len; i++ )
        output[i] = 0x00;
}

static int get_zeros_padding( unsigned char *input, size_t input_len,
                              size_t *data_len )
{
    size_t i;
    unsigned char done = 0, prev_done;

    if( NULL == input || NULL == data_len )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    *data_len = 0;
    for( i = input_len; i > 0; i-- )
    {
        prev_done = done;
        done |= ( input[i-1] != 0 );
        *data_len |= i * ( done != prev_done );
    }

    return( 0 );
}
#endif /* IOTEX_CIPHER_PADDING_ZEROS */

/*
 * No padding: don't pad :)
 *
 * There is no add_padding function (check for NULL in iotex_cipher_finish)
 * but a trivial get_padding function
 */
static int get_no_padding( unsigned char *input, size_t input_len,
                              size_t *data_len )
{
    if( NULL == input || NULL == data_len )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    *data_len = input_len;

    return( 0 );
}
#endif /* IOTEX_CIPHER_MODE_WITH_PADDING */

int32_t iotex_int_to_string(uint32_t N, char *str)
{
    int i = 0, j = 0;
    char stack[32] = {0};    
         
    while ((N / 10) != 0) {

        stack[i] = (char)((N % 10) + 48);
        N = N / 10;
        i++;

    }

    stack[i] = (char)(N + 48); 

    for (j = i; j >= 0; j--)
        str[i-j]=stack[j];
    
    str[i + 1] = '0';

    return i;
}

/****************************************************************/
/* MD */
/****************************************************************/

inline iotex_md_type_t iotex_md_get_type( const iotex_md_info_t *md_info )
{
    return (iotex_md_type_t)0;
}


/****************************************************************/
/* MD5 */
/****************************************************************/
inline void iotex_md5_free( iotex_md5_context *ctx )
{
    // TODO iotex_md5_init( (iotex_md5_context *)ctx );    
}

inline void iotex_md5_clone( iotex_md5_context *dst, const iotex_md5_context *src )
{
    // TODO iotex_md5_clone( (iotex_md5_context *)dst, (iotex_md5_context *)src );
}

inline int iotex_md5_starts( iotex_md5_context *ctx )
{
    // TODO return iotex_md5_starts_ret( (iotex_md5_context *)ctx );
	return 0;
}

inline int iotex_md5_update( iotex_md5_context *ctx, const unsigned char *input, size_t ilen )
{
    // TODO return iotex_md5_update_ret( (iotex_md5_context *)ctx, input, ilen );
	return 0;
}

inline int iotex_md5_finish( iotex_md5_context *ctx, unsigned char output[16] )
{
    // TODO return iotex_md5_finish_ret( (iotex_md5_context *)ctx, output );
	return 0;
}

inline int iotex_md5( const unsigned char *input, size_t ilen, unsigned char output[16] )
{
    // TODO return iotex_md5_ret( input, ilen, output[16] );
	return 0;
}

/****************************************************************/
/* SHA1 */
/****************************************************************/
inline void iotex_sha1_init( iotex_sha1_context *ctx )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	mbedtls_sha1_init( (mbedtls_sha1_context *)ctx );
#endif
}
 
inline void iotex_sha1_free( iotex_sha1_context *ctx )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	mbedtls_sha1_free( (mbedtls_sha1_context *)ctx );
#endif
}

inline void iotex_sha1_clone( iotex_sha1_context *dst, const iotex_sha1_context *src )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	mbedtls_sha1_clone( (mbedtls_sha1_context *)dst, (const mbedtls_sha1_context *)src );
#endif
}

inline int iotex_sha1_starts( iotex_sha1_context *ctx )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_sha1_starts( (mbedtls_sha1_context *)ctx );
#else
	return 0;
#endif
}

inline int iotex_sha1_update( iotex_sha1_context *ctx, const unsigned char *input, size_t ilen )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_sha1_update( (mbedtls_sha1_context *)ctx, input, ilen );
#else
	return 0;
#endif
}

inline int iotex_sha1_finish( iotex_sha1_context *ctx, unsigned char output[20] )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_sha1_finish( (mbedtls_sha1_context *)ctx, output );
#else
	return 0;
#endif
}

inline int iotex_internal_sha1_process( iotex_sha1_context *ctx, const unsigned char data[64] )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_internal_sha1_process( (mbedtls_sha1_context *)ctx, data );
#else
	return 0;
#endif
}

inline int iotex_sha1( const unsigned char *input, size_t ilen, unsigned char output[20] )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_sha1( input, ilen, output );
#else
	return 0;
#endif
}

/****************************************************************/
/* SHA256 */
/****************************************************************/        
inline void iotex_sha256_init( iotex_sha256_context *ctx )
{
#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    ctx->sha256_ctx = malloc(sizeof(struct tc_sha256_state_struct));

    if(ctx->sha256_ctx)
        (void)tc_sha256_init((TCSha256State_t)ctx->sha256_ctx);
#endif

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    mbedtls_sha256_init( (mbedtls_sha256_context *)ctx );
#endif
}

inline void iotex_sha256_free( iotex_sha256_context *ctx )
{
#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    if(ctx->sha256_ctx)
    {
        free(ctx->sha256_ctx);
        ctx->sha256_ctx = NULL;
    }        
#endif

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    mbedtls_sha256_free( (mbedtls_sha256_context *)ctx );
#endif
}

inline void iotex_sha256_clone( iotex_sha256_context *dst, const iotex_sha256_context *src )
{
#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
	if (NULL == dst->sha256_ctx)
		iotex_sha256_init(dst);

    memcpy(dst, src, sizeof(iotex_sha256_context));
    // Deep clone the sha256 context, which is dynamically allocated
    // Otherwise, when aborting the source operation, the sha256 context of the destination will be freed.
    dst->sha256_ctx = malloc(sizeof(struct tc_sha256_state_struct));
    memcpy(dst->sha256_ctx, src->sha256_ctx, sizeof(struct tc_sha256_state_struct));
#endif

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    mbedtls_sha256_clone( (mbedtls_sha256_context *)dst, (const mbedtls_sha256_context *)src );
#endif
}

inline int iotex_sha256_starts( iotex_sha256_context *ctx, int is224 )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_sha256_starts( (mbedtls_sha256_context *)ctx, is224 );
#else
	return 0;
#endif
}

inline int iotex_sha256_update( iotex_sha256_context *ctx, const unsigned char *input, size_t ilen )
{
#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    int ret = tc_sha256_update ((TCSha256State_t)ctx->sha256_ctx, input, ilen);
    if (TC_CRYPTO_FAIL == ret)
        return PSA_ERROR_GENERIC_ERROR;

    return PSA_SUCCESS;
#endif

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    return mbedtls_sha256_update( (mbedtls_sha256_context *)ctx, input, ilen );
#endif
}

inline int iotex_sha256_finish( iotex_sha256_context *ctx, unsigned char *output )
{
#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    int ret = tc_sha256_final(output, (TCSha256State_t)ctx->sha256_ctx);
    if (TC_CRYPTO_FAIL == ret)
        return PSA_ERROR_GENERIC_ERROR;

    return PSA_SUCCESS;
#endif

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    return mbedtls_sha256_finish( (mbedtls_sha256_context *)ctx, output );
#endif
}

inline int iotex_internal_sha256_process( iotex_sha256_context *ctx, const unsigned char data[64] )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_internal_sha256_process( (mbedtls_sha256_context *)ctx, data);
#else
	return 0;
#endif
}

inline int iotex_sha256( const unsigned char *input, size_t ilen, unsigned char *output, int is224 )
{
#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    struct tc_sha256_state_struct s;

    (void)tc_sha256_init(&s);
    tc_sha256_update(&s, (const uint8_t *) input, ilen);
    (void) tc_sha256_final(output, &s);

    return 0;
#endif


#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    return mbedtls_sha256( input, ilen, output, is224 );
#endif
}

/****************************************************************/
/* SHA512 */
/****************************************************************/
inline void iotex_sha512_init( iotex_sha512_context *ctx )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    mbedtls_sha512_init( (mbedtls_sha512_context *)ctx );
#endif

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    ctx->sha512_ctx = malloc(sizeof(struct tc_sha256_state_struct));

    if(ctx->sha512_ctx)
        (void)tc_sha256_init((TCSha256State_t)ctx->sha512_ctx);
#endif
}

inline void iotex_sha512_free( iotex_sha512_context *ctx )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    mbedtls_sha512_free( (mbedtls_sha512_context *)ctx );
#endif

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    if(ctx->sha512_ctx)
    {
        free(ctx->sha512_ctx);
        ctx->sha512_ctx = NULL;
    }        
#endif
}

inline void iotex_sha512_clone( iotex_sha512_context *dst, const iotex_sha512_context *src )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    mbedtls_sha512_clone( (mbedtls_sha512_context *)dst, (const mbedtls_sha512_context *)src );
#endif

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
	if (NULL == dst->sha512_ctx)
		iotex_sha512_init(dst);

    memcpy(dst, src, sizeof(iotex_sha512_context));
    // Deep clone the sha256 context, which is dynamically allocated
    // Otherwise, when aborting the source operation, the sha256 context of the destination will be freed.
    dst->sha512_ctx = malloc(sizeof(struct tc_sha512_state_struct));
    memcpy(dst->sha512_ctx, src->sha512_ctx, sizeof(struct tc_sha512_state_struct));
#endif
}

inline int iotex_sha512_starts( iotex_sha512_context *ctx, int is384 )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
	return mbedtls_sha512_starts( (mbedtls_sha512_context *)ctx, is384 );
#else
	return 0;
#endif
}

inline int iotex_sha512_update( iotex_sha512_context *ctx, const unsigned char *input, size_t ilen )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    return mbedtls_sha512_update( (mbedtls_sha512_context *)ctx, input, ilen );
#endif

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    (void)tc_sha512_update ((TCSha512State_t)ctx->sha512_ctx, input, ilen);

    return 0;
#endif
}

inline int iotex_sha512_finish( iotex_sha512_context *ctx, unsigned char *output )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    return mbedtls_sha512_finish( (mbedtls_sha512_context *)ctx, output );
#endif

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    (void)tc_sha512_final((TCSha512State_t)ctx->sha512_ctx, output);

    return 0;
#endif
}

inline int iotex_sha512( const unsigned char *input, size_t ilen, unsigned char *output, int is384 )
{
#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
    return mbedtls_sha512( input, ilen, output, is384 );
#endif

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
    return tc_sha512(input, ilen, output);
#endif
}

/****************************************************************/
/* RIPEMD160 */
/****************************************************************/
inline void iotex_ripemd160_init( iotex_ripemd160_context *ctx )
{
    // iotex_ripemd160_init( (iotex_ripemd160_context *)ctx );
}

inline void iotex_ripemd160_free( iotex_ripemd160_context *ctx )
{
    // iotex_ripemd160_free( (iotex_ripemd160_context *)ctx );
}

inline void iotex_ripemd160_clone( iotex_ripemd160_context *dst, const iotex_ripemd160_context *src )
{
    // iotex_ripemd160_clone( (iotex_ripemd160_context *)dst, (const iotex_ripemd160_context *)src );
}

inline int iotex_ripemd160_starts( iotex_ripemd160_context *ctx )
{
    // return iotex_ripemd160_starts_ret( (iotex_ripemd160_context *)ctx );
	return 0;
}

inline int iotex_ripemd160_update( iotex_ripemd160_context *ctx, const unsigned char *input, size_t ilen )
{
    // return iotex_ripemd160_update_ret( (iotex_ripemd160_context *)ctx, input, ilen );
	return 0;
}

inline int iotex_ripemd160_finish( iotex_ripemd160_context *ctx, unsigned char output[20] )
{
    // return iotex_ripemd160_finish_ret( (iotex_ripemd160_context *)ctx, output );
	return 0;
}

inline int iotex_ripemd160( const unsigned char *input, size_t ilen, unsigned char output[20] )
{
    // return iotex_ripemd160_ret( input, ilen, output );
	return 0;
}

/****************************************************************/
/* MAC */
/****************************************************************/
inline int iotex_cipher_cmac_starts( iotex_cipher_context_t *ctx,
                                const unsigned char *key, size_t keybits )
{
    // return iotex_cipher_cmac_starts( (iotex_cipher_context_t *)ctx, key, keybits );
	return 0;
}

inline int iotex_cipher_cmac_update( iotex_cipher_context_t *ctx,
                                const unsigned char *input, size_t ilen )
{
    // return iotex_cipher_cmac_update( (iotex_cipher_context_t *)ctx, input, ilen );
	return 0;
}

inline int iotex_cipher_cmac_finish( iotex_cipher_context_t *ctx,
                                unsigned char *output )
{
    // return iotex_cipher_cmac_finish( (iotex_cipher_context_t *)ctx, output );
	return 0;
}                                

inline int iotex_cipher_cmac_reset( iotex_cipher_context_t *ctx )
{
    // return iotex_cipher_cmac_reset( (iotex_cipher_context_t *)ctx );
	return 0;
}

inline int iotex_cipher_cmac( const iotex_cipher_info_t *cipher_info,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output )
{
    // return iotex_cipher_cmac( (iotex_cipher_info_t *)cipher_info, key, keylen, input, ilen, output );
	return 0;
}

#if defined(IOTEX_AES_C)
inline int iotex_aes_cmac_prf_128( const unsigned char *key, size_t key_len,
                              const unsigned char *input, size_t in_len,
                              unsigned char output[16] )
{
    // return iotex_aes_cmac_prf_128( key, key_len, input, in_len, output );
	return 0;
}
#endif /* IOTEX_AES_C */

psa_status_t iotex_psa_mac_compute( const psa_key_attributes_t *attributes,
                            const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg,
                            const uint8_t *input, size_t input_length,
                            uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    int ret = TC_CRYPTO_SUCCESS;

    if ( NULL == key_buffer || 0 == key_buffer_size )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if ( NULL == input || 0 == input_length )
        return( PSA_ERROR_INVALID_ARGUMENT );    

    if ( NULL == mac || 0 == mac_size || NULL == mac_length )
        return( PSA_ERROR_INVALID_ARGUMENT ); 

    if( ! PSA_ALG_IS_MAC( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    uint32_t hash_alg =  PSA_ALG_HMAC_GET_HASH( alg );

    if ( PSA_ALG_SHA_256 == hash_alg ) {
    
        tc_hmac_init(&hmac_ctx);
        tc_hmac_set_key(&hmac_ctx, key_buffer, key_buffer_size);
        tc_hmac_update(&hmac_ctx, input, input_length);
        ret = tc_hmac_final(mac, mac_size, &hmac_ctx);
        if ( TC_CRYPTO_SUCCESS == ret ) {
            *mac_length = TC_SHA256_DIGEST_SIZE;
            return PSA_SUCCESS;
        } else    
            return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t iotex_psa_mac_sign_setup( iotex_psa_mac_operation_t *operation,
                        const psa_key_attributes_t *attributes,
                        const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{
    if ( NULL == key_buffer || 0 == key_buffer_size )
        return ( PSA_ERROR_INVALID_ARGUMENT );

    if( ! PSA_ALG_IS_MAC( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    uint32_t hash_alg =  PSA_ALG_HMAC_GET_HASH( alg );  
    if ( PSA_ALG_SHA_256 == hash_alg ) {
        tc_hmac_init(&hmac_ctx);
        tc_hmac_set_key(&hmac_ctx, key_buffer, key_buffer_size);

        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t iotex_psa_mac_verify_setup( iotex_psa_mac_operation_t *operation,
                        const psa_key_attributes_t *attributes,
                        const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{
    return iotex_psa_mac_sign_setup(operation, attributes, key_buffer, key_buffer_size, alg);        
}

psa_status_t iotex_psa_mac_update( iotex_psa_mac_operation_t *operation,
                        const uint8_t *input, size_t input_length )
{
    int ret;

    if ( NULL == input || 0 == input_length )
        return PSA_ERROR_INVALID_ARGUMENT;

    ret = tc_hmac_update(&hmac_ctx, input, input_length);
    if ( TC_CRYPTO_SUCCESS == ret )
        return PSA_SUCCESS;
    else
        return PSA_ERROR_COMMUNICATION_FAILURE;                
}

psa_status_t iotex_psa_mac_sign_finish( iotex_psa_mac_operation_t *operation,
                    uint8_t *mac, size_t mac_size, size_t *mac_length )
{
    int ret;
    
    if ( NULL == mac || 0 == mac_size || NULL == mac_length )
        return PSA_ERROR_INVALID_ARGUMENT;

    *mac_length = 0;

    ret = tc_hmac_final(mac, mac_size, &hmac_ctx);  
    if ( TC_CRYPTO_SUCCESS == ret ) {
        *mac_length = TC_SHA256_DIGEST_SIZE;
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }                  
}

/****************************************************************/
/* CAMELLIA */
/****************************************************************/

inline void iotex_camellia_init( iotex_camellia_context *ctx )
{
    // iotex_camellia_init( (iotex_camellia_context *)ctx );
}

inline void iotex_camellia_free( iotex_camellia_context *ctx )
{
    // iotex_camellia_free( (iotex_camellia_context *)ctx );
}

inline int iotex_camellia_setkey_enc( iotex_camellia_context *ctx,
                                 const unsigned char *key,
                                 unsigned int keybits )
{
    // return iotex_camellia_setkey_enc( (iotex_camellia_context *)ctx, key, keybits );
	return 0;
}

inline int iotex_camellia_setkey_dec( iotex_camellia_context *ctx,
                                 const unsigned char *key,
                                 unsigned int keybits )
{
    // return iotex_camellia_setkey_dec( (iotex_camellia_context *)ctx, key, keybits );
	return 0;
}

inline int iotex_camellia_crypt_ecb( iotex_camellia_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
    // return iotex_camellia_crypt_ecb( (iotex_camellia_context *)ctx, mode, input, output );
	return 0;
}

#if defined(IOTEX_CIPHER_MODE_CBC)
inline int iotex_camellia_crypt_cbc( iotex_camellia_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    // return iotex_camellia_crypt_cbc( (iotex_camellia_context *)ctx, mode, length, iv, input, output );
	return 0;
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
inline int iotex_camellia_crypt_cfb128( iotex_camellia_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    // return iotex_camellia_crypt_cfb128( (iotex_camellia_context *)ctx, mode, length, iv_off, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
inline int iotex_camellia_crypt_ctr( iotex_camellia_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    // return iotex_camellia_crypt_ctr( (iotex_camellia_context *)ctx, length, nc_off, nonce_counter, stream_block, input, output );
	return 0;
}
#endif /* IOTEX_CIPHER_MODE_CTR */

/****************************************************************/
/* CIPHER */
/****************************************************************/
inline const int *iotex_cipher_list( void )
{
    // return iotex_cipher_list();
	return 0;
}

inline const iotex_cipher_info_t *iotex_cipher_info_from_string( const char *cipher_name )
{
    // return (iotex_cipher_info_t *)(iotex_cipher_info_from_string(cipher_name));
	return 0;
}

inline const iotex_cipher_info_t *iotex_cipher_info_from_type( const iotex_cipher_type_t cipher_type )
{
    // return (iotex_cipher_info_t *)(iotex_cipher_info_from_type( (iotex_cipher_type_t)cipher_type));
	return 0;
}

const iotex_cipher_info_t *iotex_cipher_info_from_values(const iotex_cipher_id_t cipher_id, int key_bitlen, const iotex_cipher_mode_t mode ) 
{
    const iotex_cipher_definition_t *def;

    for( def = iotex_cipher_definitions; def->info != NULL; def++ )
        if( def->info->base->cipher == cipher_id &&
            def->info->key_bitlen == (unsigned) key_bitlen &&
            def->info->mode == mode )
            return( def->info );

    return( NULL );
}

void iotex_cipher_init( iotex_cipher_context_t *ctx )
{
    if(ctx == NULL)
        return;

    memset( ctx, 0, sizeof(iotex_cipher_context_t));
}

void iotex_cipher_free( iotex_cipher_context_t *ctx )
{
    if( ctx == NULL )
        return;

    if( ctx->cipher_ctx != NULL )
    {
        iotex_cipher_context_psa * const cipher_psa =
            (iotex_cipher_context_psa *) ctx->cipher_ctx;

        if( cipher_psa->slot_state == IOTEX_CIPHER_PSA_KEY_OWNED )
        {
            (void) psa_destroy_key( cipher_psa->slot );
        }

        iotex_platform_zeroize( ctx->cipher_ctx, sizeof( *cipher_psa ) );
        iotex_free( cipher_psa );
    }

    iotex_platform_zeroize( ctx, sizeof(iotex_cipher_context_t) );

    if( ctx->cipher_ctx )
        ctx->cipher_info->base->ctx_free_func( ctx->cipher_ctx );

    iotex_platform_zeroize( ctx, sizeof(iotex_cipher_context_t) );           
}

inline int iotex_cipher_setup( iotex_cipher_context_t *ctx, const iotex_cipher_info_t *cipher_info )
{
    if( ctx == NULL )
        return IOTEX_ERR_CIPHER_BAD_INPUT_DATA;

    if( cipher_info == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    memset( ctx, 0, sizeof( iotex_cipher_context_t ) );
    
    if( NULL == ( ctx->cipher_ctx = cipher_info->base->ctx_alloc_func() ) )
        return( IOTEX_ERR_CIPHER_ALLOC_FAILED );

    ctx->cipher_info = (iotex_cipher_info_t *)cipher_info;

#if defined(IOTEX_CIPHER_MODE_WITH_PADDING)
    /*
     * Ignore possible errors caused by a cipher mode that doesn't use padding
     */
#if defined(IOTEX_CIPHER_PADDING_PKCS7)
    (void) iotex_cipher_set_padding_mode( ctx, IOTEX_PADDING_PKCS7 );
#else
    (void) iotex_cipher_set_padding_mode( ctx, IOTEX_PADDING_NONE );
#endif
#endif /* IOTEX_CIPHER_MODE_WITH_PADDING */

    return( 0 );
}

inline int iotex_cipher_setkey( iotex_cipher_context_t *ctx, const unsigned char *key, int key_bitlen, const iotex_operation_t operation )
{
    if( ctx == NULL || key == NULL)
        return IOTEX_ERR_CIPHER_BAD_INPUT_DATA;

    if ( operation != IOTEX_ENCRYPT && operation != IOTEX_DECRYPT )
        return IOTEX_ERR_CIPHER_BAD_INPUT_DATA;

    if( ctx->cipher_info == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if( ( ctx->cipher_info->flags & IOTEX_CIPHER_VARIABLE_KEY_LEN ) == 0 &&
        (int) ctx->cipher_info->key_bitlen != key_bitlen )
    {
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

    /*
     * For OFB, CFB and CTR mode always use the encryption key schedule
     */
    if( IOTEX_ENCRYPT == operation ||
        IOTEX_MODE_CFB == ctx->cipher_info->mode ||
        IOTEX_MODE_OFB == ctx->cipher_info->mode ||
        IOTEX_MODE_CTR == ctx->cipher_info->mode )
    {
        return( ctx->cipher_info->base->setkey_enc_func( ctx->cipher_ctx, key,
                                                         ctx->key_bitlen ) );
    }

    if( IOTEX_DECRYPT == operation )
        return( ctx->cipher_info->base->setkey_dec_func( ctx->cipher_ctx, key,
                                                         ctx->key_bitlen ) );

    return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
}

#if defined(IOTEX_CIPHER_MODE_WITH_PADDING)
inline int iotex_cipher_set_padding_mode( iotex_cipher_context_t *ctx, iotex_cipher_padding_t mode )
{
    if ( ctx == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if( NULL == ctx->cipher_info || IOTEX_MODE_CBC != ctx->cipher_info->mode )
    {
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    }

    switch( mode )
    {
#if defined(IOTEX_CIPHER_PADDING_PKCS7)
    case IOTEX_PADDING_PKCS7:
        ctx->add_padding = add_pkcs_padding;
        ctx->get_padding = get_pkcs_padding;
        break;
#endif
#if defined(IOTEX_CIPHER_PADDING_ONE_AND_ZEROS)
    case IOTEX_PADDING_ONE_AND_ZEROS:
        ctx->add_padding = add_one_and_zeros_padding;
        ctx->get_padding = get_one_and_zeros_padding;
        break;
#endif
#if defined(IOTEX_CIPHER_PADDING_ZEROS_AND_LEN)
    case IOTEX_PADDING_ZEROS_AND_LEN:
        ctx->add_padding = add_zeros_and_len_padding;
        ctx->get_padding = get_zeros_and_len_padding;
        break;
#endif
#if defined(IOTEX_CIPHER_PADDING_ZEROS)
    case IOTEX_PADDING_ZEROS:
        ctx->add_padding = add_zeros_padding;
        ctx->get_padding = get_zeros_padding;
        break;
#endif
    case IOTEX_PADDING_NONE:
        ctx->add_padding = NULL;
        ctx->get_padding = get_no_padding;
        break;

    default:
        return( IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE );
    }

    return( 0 );
}
#endif /* IOTEX_CIPHER_MODE_WITH_PADDING */

inline int iotex_cipher_set_iv( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len )
{
    size_t actual_iv_size;

    if( ctx == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA ); 
    
    if( iv_len != 0 && iv == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if( ctx->cipher_info == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    /* avoid buffer overflow in ctx->iv */
    if( iv_len > IOTEX_MAX_IV_LENGTH )
        return( IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE );

    if( ( ctx->cipher_info->flags & IOTEX_CIPHER_VARIABLE_IV_LEN ) != 0 )
        actual_iv_size = iv_len;
    else
    {
        actual_iv_size = ctx->cipher_info->iv_size;

        /* avoid reading past the end of input buffer */
        if( actual_iv_size > iv_len )
            return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    }
    
#if defined(IOTEX_CHACHA20_C)
    if ( ctx->cipher_info->type == IOTEX_CIPHER_CHACHA20 )
    {
        /* Even though the actual_iv_size is overwritten with a correct value
         * of 12 from the cipher info, return an error to indicate that
         * the input iv_len is wrong. */
        if( iv_len != 12 )
            return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

        if ( 0 != iotex_chacha20_starts( (iotex_chacha20_context*)ctx->cipher_ctx,
                                           iv,
                                           0U ) ) /* Initial counter value */
        {
            return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
        }
    }
#if defined(IOTEX_CHACHAPOLY_C)
    if ( ctx->cipher_info->type == IOTEX_CIPHER_CHACHA20_POLY1305 &&
         iv_len != 12 )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
#endif
#endif

#if defined(IOTEX_GCM_C)
    if( IOTEX_MODE_GCM == ctx->cipher_info->mode )
    {
        return( iotex_gcm_starts( (iotex_gcm_context *) ctx->cipher_ctx,
                                    ctx->operation,
                                    iv, iv_len ) );
    }
#endif

#if defined(IOTEX_CCM_C)
    if( IOTEX_MODE_CCM_STAR_NO_TAG == ctx->cipher_info->mode )
    {
        int set_lengths_result;
        int ccm_star_mode;

        set_lengths_result = iotex_ccm_set_lengths(
                                (iotex_ccm_context *) ctx->cipher_ctx,
                                0, 0, 0 );
        if( set_lengths_result != 0 )
            return set_lengths_result;

        if( ctx->operation == IOTEX_DECRYPT )
            ccm_star_mode = IOTEX_CCM_STAR_DECRYPT;
        else if( ctx->operation == IOTEX_ENCRYPT )
            ccm_star_mode = IOTEX_CCM_STAR_ENCRYPT;
        else
            return IOTEX_ERR_CIPHER_BAD_INPUT_DATA;

        return( iotex_ccm_starts( (iotex_ccm_context *) ctx->cipher_ctx,
                                    ccm_star_mode,
                                    iv, iv_len ) );
        return 0;
    }
#endif
    if ( actual_iv_size != 0 )
    {
        memcpy( ctx->iv, iv, actual_iv_size );
        ctx->iv_size = actual_iv_size;
    }

    return( 0 );
}

inline int iotex_cipher_reset( iotex_cipher_context_t *ctx )
{
    if( ctx == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    if( ctx->cipher_info == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

#if defined(IOTEX_USE_PSA_CRYPTO)
    if( ctx->psa_enabled == 1 )
    {
        /* We don't support resetting PSA-based
         * cipher contexts, yet. */
        return( IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE );
    }
#endif /* IOTEX_USE_PSA_CRYPTO */

    ctx->unprocessed_len = 0;

    return( 0 );
}

#if defined(IOTEX_GCM_C) || defined(IOTEX_CHACHAPOLY_C)
inline int iotex_cipher_update_ad( iotex_cipher_context_t *ctx, const unsigned char *ad, size_t ad_len )
{
    // TODO iotex_cipher_update_ad( (iotex_cipher_context_t *)ctx, ad, ad_len );
}
#endif /* IOTEX_GCM_C || IOTEX_CHACHAPOLY_C */

int iotex_cipher_update( iotex_cipher_context_t *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen )
{
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    size_t block_size;

    if ( ctx == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if ( ilen == 0 || input == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if ( output == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if ( olen == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    if( ctx->cipher_info == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    
    *olen = 0;
    block_size = iotex_cipher_get_block_size( ctx );
    if ( 0 == block_size )
    {
        return( IOTEX_ERR_CIPHER_INVALID_CONTEXT );
    }

    if( ctx->cipher_info->mode == IOTEX_MODE_ECB )
    {
        if( ilen != block_size )
            return( IOTEX_ERR_CIPHER_FULL_BLOCK_EXPECTED );

        *olen = ilen;

        if( 0 != ( ret = ctx->cipher_info->base->ecb_func( ctx->cipher_ctx,
                    ctx->operation, input, output ) ) )
        {
            return( ret );
        }

        return( 0 );
    }

#if defined(IOTEX_GCM_C)
    if( ctx->cipher_info->mode == IOTEX_MODE_GCM )
    {
        return( iotex_gcm_update( (iotex_gcm_context *) ctx->cipher_ctx,
                                    input, ilen,
                                    output, ilen, olen ) );
    }
#endif

#if defined(IOTEX_CCM_C)
    if( ctx->cipher_info->mode == IOTEX_MODE_CCM_STAR_NO_TAG )
    {
        return( iotex_ccm_update( (iotex_ccm_context *) ctx->cipher_ctx,
                                    input, ilen,
                                    output, ilen, olen ) );
    }
#endif

#if defined(IOTEX_CHACHAPOLY_C)
    if ( ctx->cipher_info->type == IOTEX_CIPHER_CHACHA20_POLY1305 )
    {
        *olen = ilen;
        return( iotex_chachapoly_update( (iotex_chachapoly_context*) ctx->cipher_ctx,
                                           ilen, input, output ) );
    }
#endif

    if( input == output &&
       ( ctx->unprocessed_len != 0 || ilen % block_size ) )
    {
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    }

#if defined(IOTEX_CIPHER_MODE_CBC)
    if( ctx->cipher_info->mode == IOTEX_MODE_CBC )
    {
        size_t copy_len = 0;
        /*
         * If there is not enough data for a full block, cache it.
         */
        if( ( ctx->operation == IOTEX_DECRYPT && NULL != ctx->add_padding &&
                ilen <= block_size - ctx->unprocessed_len ) ||
            ( ctx->operation == IOTEX_DECRYPT && NULL == ctx->add_padding &&
                ilen < block_size - ctx->unprocessed_len ) ||
             ( ctx->operation == IOTEX_ENCRYPT &&
                ilen < block_size - ctx->unprocessed_len ) )
        {
            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    ilen );

            ctx->unprocessed_len += ilen;
            return( 0 );
        }
        /*
         * Process cached data first
         */
        if( 0 != ctx->unprocessed_len )
        {
            copy_len = block_size - ctx->unprocessed_len;

            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    copy_len );

            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, block_size, ctx->iv,
                    ctx->unprocessed_data, output ) ) )
            {
                return( ret );
            }

            *olen += block_size;
            output += block_size;
            ctx->unprocessed_len = 0;

            input += copy_len;
            ilen -= copy_len;
        }
        /*
         * Cache final, incomplete block
         */
        if( 0 != ilen )
        {
            /* Encryption: only cache partial blocks
             * Decryption w/ padding: always keep at least one whole block
             * Decryption w/o padding: only cache partial blocks
             */
            copy_len = ilen % block_size;
            if( copy_len == 0 &&
                ctx->operation == IOTEX_DECRYPT &&
                NULL != ctx->add_padding)
            {
                copy_len = block_size;
            }

            memcpy( ctx->unprocessed_data, &( input[ilen - copy_len] ),
                    copy_len );

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if( ilen )
        {
            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, ilen, ctx->iv, input, output ) ) )
            {
                return( ret );
            }
            
            *olen += ilen;
        }

        return( 0 );
    }
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
    if( ctx->cipher_info->mode == IOTEX_MODE_CFB )
    {
        if( 0 != ( ret = ctx->cipher_info->base->cfb_func( ctx->cipher_ctx,
                ctx->operation, ilen, &ctx->unprocessed_len, ctx->iv,
                input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_OFB)
    if( ctx->cipher_info->mode == IOTEX_MODE_OFB )
    {
        if( 0 != ( ret = ctx->cipher_info->base->ofb_func( ctx->cipher_ctx,
                ilen, &ctx->unprocessed_len, ctx->iv, input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* IOTEX_CIPHER_MODE_OFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
    if( ctx->cipher_info->mode == IOTEX_MODE_CTR )
    {
        if( 0 != ( ret = ctx->cipher_info->base->ctr_func( ctx->cipher_ctx,
                ilen, &ctx->unprocessed_len, ctx->iv,
                ctx->unprocessed_data, input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* IOTEX_CIPHER_MODE_CTR */

#if defined(IOTEX_CIPHER_MODE_XTS)
    if( ctx->cipher_info->mode == IOTEX_MODE_XTS )
    {
        if( ctx->unprocessed_len > 0 ) {
            /* We can only process an entire data unit at a time. */
            return( IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE );
        }

        ret = ctx->cipher_info->base->xts_func( ctx->cipher_ctx,
                ctx->operation, ilen, ctx->iv, input, output );
        if( ret != 0 )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* IOTEX_CIPHER_MODE_XTS */

#if defined(IOTEX_CIPHER_MODE_STREAM)
    if( ctx->cipher_info->mode == IOTEX_MODE_STREAM )
    {
        if( 0 != ( ret = ctx->cipher_info->base->stream_func( ctx->cipher_ctx,
                                                    ilen, input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* IOTEX_CIPHER_MODE_STREAM */

    return( IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE );
}

int iotex_cipher_finish( iotex_cipher_context_t *ctx, unsigned char *output, size_t *olen )
{
    if ( ctx == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    if ( output == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    if ( olen == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );
    if( ctx->cipher_info == NULL )
        return( IOTEX_ERR_CIPHER_BAD_INPUT_DATA );

    *olen = 0;

    if( IOTEX_MODE_CFB == ctx->cipher_info->mode ||
        IOTEX_MODE_OFB == ctx->cipher_info->mode ||
        IOTEX_MODE_CTR == ctx->cipher_info->mode ||
        IOTEX_MODE_GCM == ctx->cipher_info->mode ||
        IOTEX_MODE_CCM_STAR_NO_TAG == ctx->cipher_info->mode ||
        IOTEX_MODE_XTS == ctx->cipher_info->mode ||
        IOTEX_MODE_STREAM == ctx->cipher_info->mode )
    {
        return( 0 );
    }

    if ( ( IOTEX_CIPHER_CHACHA20          == ctx->cipher_info->type ) ||
         ( IOTEX_CIPHER_CHACHA20_POLY1305 == ctx->cipher_info->type ) )
    {
        return( 0 );
    }

    if( IOTEX_MODE_ECB == ctx->cipher_info->mode )
    {
        if( ctx->unprocessed_len != 0 )
            return( IOTEX_ERR_CIPHER_FULL_BLOCK_EXPECTED );

        return( 0 );
    }

#if defined(IOTEX_CIPHER_MODE_CBC)
    if( IOTEX_MODE_CBC == ctx->cipher_info->mode )
    {
        int ret = 0;
    
        if( IOTEX_ENCRYPT == ctx->operation )
        {
            /* check for 'no padding' mode */
            if( NULL == ctx->add_padding )
            {
                if( 0 != ctx->unprocessed_len )
                    return( IOTEX_ERR_CIPHER_FULL_BLOCK_EXPECTED );

                return( 0 );
            }

            ctx->add_padding( ctx->unprocessed_data, iotex_cipher_get_iv_size( ctx ),
                    ctx->unprocessed_len );
        }
        else if( iotex_cipher_get_block_size( ctx ) != ctx->unprocessed_len )
        {
            /*
             * For decrypt operations, expect a full block,
             * or an empty block if no padding
             */
            if( NULL == ctx->add_padding && 0 == ctx->unprocessed_len )
                return( 0 );
            return( IOTEX_ERR_CIPHER_FULL_BLOCK_EXPECTED );
        }
        /* cipher block */
        if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                ctx->operation, iotex_cipher_get_block_size( ctx ), ctx->iv,
                ctx->unprocessed_data, output ) ) )
        {
            return( ret );
        }

        /* Set output size for decryption */
        if( IOTEX_DECRYPT == ctx->operation )
        {
            return( ctx->get_padding( output, iotex_cipher_get_block_size( ctx ),
                                      olen ) );
        }

        /* Set output size for encryption */
        *olen = iotex_cipher_get_block_size( ctx );
        return( 0 );
    }
#else
    ((void) output);
#endif /* IOTEX_CIPHER_MODE_CBC */

    return( IOTEX_ERR_CIPHER_FEATURE_UNAVAILABLE );
}

#if defined(IOTEX_GCM_C) || defined(IOTEX_CHACHAPOLY_C)
inline int iotex_cipher_write_tag( iotex_cipher_context_t *ctx, unsigned char *tag, size_t tag_len )
{
    // TODO iotex_cipher_write_tag( (iotex_cipher_context_t *)ctx, tag, tag_len );
}

inline int iotex_cipher_check_tag( iotex_cipher_context_t *ctx, const unsigned char *tag, size_t tag_len )
{
    // TODO iotex_cipher_check_tag( (iotex_cipher_context_t *)ctx, tag, tag_len );
}
#endif /* IOTEX_GCM_C || IOTEX_CHACHAPOLY_C */

inline int iotex_cipher_crypt( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen )
{
   // TODO iotex_cipher_crypt( (iotex_cipher_context_t *)ctx,  iv, iv_len, input, ilen, output, olen );
	return 0;
}

#if defined(IOTEX_CIPHER_MODE_AEAD) || defined(IOTEX_NIST_KW_C)
inline int iotex_cipher_auth_encrypt_ext( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t output_len, size_t *olen, size_t tag_len )
{
    // TODO iotex_cipher_auth_encrypt_ext( (iotex_cipher_context_t *)ctx, iv, iv_len, ad, ad_len, input, ilen, output, output_len, olen, tag_len);
	return 0;
}

inline int iotex_cipher_auth_decrypt_ext( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t output_len, size_t *olen, size_t tag_len )
{
    // TODO iotex_cipher_auth_decrypt_ext( (iotex_cipher_context_t *)ctx, iv, iv_len, ad, ad_len, input, ilen, output, output_len, olen, tag_len );
	return 0;
}
#endif

void iotex_ccm_init( iotex_ccm_context *ctx )
{
    memset( ctx, 0, sizeof( iotex_ccm_context ) );
}

void iotex_ccm_free( iotex_ccm_context *ctx )
{
    iotex_cipher_free( &ctx->cipher_ctx );
}

int iotex_ccm_setkey( iotex_ccm_context *ctx, iotex_cipher_id_t cipher, const unsigned char *key, unsigned int keybits )
{
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    const iotex_cipher_info_t *cipher_info;

    cipher_info = iotex_cipher_info_from_values( cipher, keybits, IOTEX_MODE_ECB );
    if( cipher_info == NULL )
        return( IOTEX_ERR_CCM_BAD_INPUT );

    if( cipher_info->block_size != 16 )
        return( IOTEX_ERR_CCM_BAD_INPUT );

    iotex_cipher_free( &ctx->cipher_ctx );

    if( ( ret = iotex_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = iotex_cipher_setkey( &ctx->cipher_ctx, key, keybits, IOTEX_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int iotex_ccm_encrypt_and_tag( iotex_ccm_context *ctx, size_t length, const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len,
                         const unsigned char *input, unsigned char *output, unsigned char *tag, size_t tag_len )
{
    int ret = PSA_SUCCESS;

    tc_ccm_config(&c, &s, iv, iv_len, tag_len); 

    ret = tc_ccm_generation_encryption(output, length + tag_len, ad, ad_len, input, length, &c);  
    if (TC_CRYPTO_FAIL == ret)
        return ( PSA_ERROR_COMMUNICATION_FAILURE );
    else
        return ( PSA_SUCCESS );        
}

int iotex_ccm_auth_decrypt( iotex_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *ad, size_t ad_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
    int ret = PSA_SUCCESS;

    tc_ccm_config(&c, &s, iv, iv_len, tag_len);

    ret = tc_ccm_decryption_verification(output, length, ad, ad_len, input, length + tag_len, &c);
    if (TC_CRYPTO_FAIL == ret)
        return ( PSA_ERROR_COMMUNICATION_FAILURE );
    else
        return ( PSA_SUCCESS );
}

int iotex_ccm_set_lengths( iotex_ccm_context *ctx, size_t total_ad_len, size_t plaintext_len, size_t tag_len )
{
    return 0;
}

int iotex_ccm_starts( iotex_ccm_context *ctx, int mode, const unsigned char *iv, size_t iv_len )
{
    return 0;
}

int iotex_ccm_update( iotex_ccm_context *ctx, const unsigned char *input, size_t input_len, unsigned char *output, size_t output_size, size_t *output_len )
{
    return 0;
}

/****************************************************************/
/* AES */
/****************************************************************/
inline void iotex_aes_init( iotex_aes_context *ctx )
{
    if ( ctx == NULL )
        return;

    memset( ctx, 0, sizeof( iotex_aes_context ) );
}

inline void iotex_aes_free( iotex_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    iotex_platform_zeroize( ctx, sizeof( iotex_aes_context ) );
}

int iotex_aes_setkey_enc( iotex_aes_context *ctx, const unsigned char *key, unsigned int keybits )
{
    int ret = 0;

#if 0
    if ( keybits != 128 )
        return PSA_ERROR_NOT_SUPPORTED;

    ret = tc_aes128_set_encrypt_key(&s, key);
    if ( ret == 0 )
        return IOTEX_ERR_AES_INVALID_KEY_LENGTH;
#else
    switch (keybits)
    {
    case 128:
        tc_aes_key_sched_init(&s, TC_AES_128);
        break;
    case 192:
        tc_aes_key_sched_init(&s, TC_AES_192);
        break;
    case 256:
        tc_aes_key_sched_init(&s, TC_AES_256);
        break;             
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }  
    ret = tc_aes_set_encrypt_key(&s, key);
    if ( TC_CRYPTO_FAIL == ret )
        return IOTEX_ERR_AES_BAD_INPUT_DATA;      
#endif

    return 0;
}

inline int iotex_aes_setkey_dec( iotex_aes_context *ctx, const unsigned char *key, unsigned int keybits )
{
    int ret = 0;

#if 0
    if ( keybits != 128 )
        return PSA_ERROR_NOT_SUPPORTED;

    ret = tc_aes128_set_decrypt_key(&s, key);
    if ( ret == 0 )
        return IOTEX_ERR_AES_INVALID_KEY_LENGTH;
#else
    switch (keybits)
    {
    case 128:
        tc_aes_key_sched_init(&s, TC_AES_128);
        break;
    case 192:
        tc_aes_key_sched_init(&s, TC_AES_192);
        break;
    case 256:
        tc_aes_key_sched_init(&s, TC_AES_256);
        break;             
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }  
    ret = tc_aes_set_decrypt_key(&s, key);
    if ( TC_CRYPTO_FAIL == ret )
        return IOTEX_ERR_AES_BAD_INPUT_DATA;  
#endif
    return 0;    
}

inline int iotex_aes_crypt_ecb( iotex_aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16] )
{
    int ret = 0;

    if ( ctx == NULL )
        return (IOTEX_ERR_AES_BAD_INPUT_DATA);
    if ( mode != IOTEX_AES_ENCRYPT && mode != IOTEX_AES_DECRYPT )
        return (IOTEX_ERR_AES_BAD_INPUT_DATA);
    if ( input == NULL  || output == NULL)
        return (IOTEX_ERR_AES_BAD_INPUT_DATA);

    if( mode == IOTEX_AES_DECRYPT )
    {
        ret = tc_aes_decrypt(output, input, &s);
        if (ret != 1)
            return IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    }
    else
    {
        ret = tc_aes_encrypt(output, output, &s);
        if (ret != 1)
            return IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    }

    return 0;
}

#if defined(IOTEX_CIPHER_MODE_CBC)
int iotex_aes_crypt_cbc( iotex_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    int i;
    int ret = IOTEX_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char temp[16];

    if ( ctx == NULL )
        return (IOTEX_ERR_AES_BAD_INPUT_DATA);
    if ( mode != IOTEX_AES_ENCRYPT && mode != IOTEX_AES_DECRYPT )
        return (IOTEX_ERR_AES_BAD_INPUT_DATA);
    if ( iv == NULL )
        return (IOTEX_ERR_AES_BAD_INPUT_DATA);
    if ( input == NULL  || output == NULL)
        return (IOTEX_ERR_AES_BAD_INPUT_DATA);
    if ( length % 16 )
        return( IOTEX_ERR_AES_INVALID_INPUT_LENGTH );

    if( mode == IOTEX_AES_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            ret = tc_aes_decrypt(output, input, &s);
            if( ret != 1 )
                goto exit;

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            ret = tc_aes_encrypt(output, output, &s);
            if( ret != 1 )
                goto exit;
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    ret = 0;

exit:
    return( ret );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_XTS)
inline int iotex_aes_crypt_xts( iotex_aes_xts_context *ctx, int mode, size_t length, const unsigned char data_unit[16], const unsigned char *input, unsigned char *output )
{
    // TODO iotex_aes_crypt_xts( (iotex_aes_xts_context *)ctx, mode, length, data_unit, input, output );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

#if defined(IOTEX_CIPHER_MODE_CFB)
inline int iotex_aes_crypt_cfb128( iotex_aes_context *ctx, int mode, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    // TODO iotex_aes_crypt_cfb128( (iotex_aes_context *)ctx, mode, length, iv_off, iv, input, output );
}

inline int iotex_aes_crypt_cfb8( iotex_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    // TODO iotex_aes_crypt_cfb8( (iotex_aes_context *)ctx, mode, length, iv, input, output );
}
#endif /*IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_OFB)
int iotex_aes_crypt_ofb( iotex_aes_context *ctx, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    // TODO iotex_aes_crypt_ofb( (iotex_aes_context *)ctx, length, iv_off, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_OFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
inline int iotex_aes_crypt_ctr( iotex_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
	int ret = TC_CRYPTO_SUCCESS;
	ret = tc_ctr_mode(output, length, input, length, nonce_counter, &s);
	if( TC_CRYPTO_SUCCESS == ret )
		return 0;
	else
		return IOTEX_ERR_CIPHER_INVALID_CONTEXT;
}
#endif /* IOTEX_CIPHER_MODE_CTR */

/****************************************************************/
/* RSA */
/****************************************************************/
inline void iotex_rsa_init( iotex_rsa_context *ctx )
{
    // TODO iotex_rsa_init( (iotex_rsa_context *)ctx );
}

inline int iotex_rsa_set_padding( iotex_rsa_context *ctx, int padding,
                             iotex_md_type_t hash_id )
{     
    // TODO iotex_rsa_set_padding((iotex_rsa_context *)ctx, padding, hash_id );
	return 0;
}

inline int iotex_rsa_import( iotex_rsa_context *ctx,
                        const iotex_mpi *N,
                        const iotex_mpi *P, const iotex_mpi *Q,
                        const iotex_mpi *D, const iotex_mpi *E )
{
    // TODO iotex_rsa_import( (iotex_rsa_context *)ctx, (iotex_mpi *)N, (iotex_mpi *)P, (iotex_mpi *)Q, (iotex_mpi *)D, (iotex_mpi *)E );
	return 0;
}

inline int iotex_rsa_import_raw( iotex_rsa_context *ctx,
                            unsigned char const *N, size_t N_len,
                            unsigned char const *P, size_t P_len,
                            unsigned char const *Q, size_t Q_len,
                            unsigned char const *D, size_t D_len,
                            unsigned char const *E, size_t E_len )
{
    // TODO iotex_rsa_import_raw( (iotex_rsa_context *)ctx, N, N_len, P, P_len, Q, Q_len, D, D_len, E, E_len );
	return 0;
}

inline int iotex_rsa_complete( iotex_rsa_context *ctx )
{
    // TODO iotex_rsa_complete( (iotex_rsa_context *)ctx );
	return 0;
}

inline int iotex_rsa_export( const iotex_rsa_context *ctx,
                        iotex_mpi *N, iotex_mpi *P, iotex_mpi *Q,
                        iotex_mpi *D, iotex_mpi *E )
{
    // TODO iotex_rsa_export( (iotex_rsa_context *)ctx,
    //                    (iotex_mpi *)N, (iotex_mpi *)P, (iotex_mpi *)Q, (iotex_mpi *)D, (iotex_mpi *)E );
	return 0;
}

inline int iotex_rsa_export_raw( const iotex_rsa_context *ctx,
                            unsigned char *N, size_t N_len,
                            unsigned char *P, size_t P_len,
                            unsigned char *Q, size_t Q_len,
                            unsigned char *D, size_t D_len,
                            unsigned char *E, size_t E_len )
{
    // return iotex_rsa_export_raw( (iotex_rsa_context *)ctx, N, N_len, P, P_len, Q, Q_len, D, D_len, E, E_len );
	return 0;
}

inline int iotex_rsa_export_crt( const iotex_rsa_context *ctx,
                            iotex_mpi *DP, iotex_mpi *DQ, iotex_mpi *QP )
{
    // return iotex_rsa_export_crt( (iotex_rsa_context *)ctx,
    //                        (iotex_mpi *)DP, (iotex_mpi *)DQ, (iotex_mpi *)QP );
	return 0;
}

inline size_t iotex_rsa_get_len( const iotex_rsa_context *ctx )
{
    // return iotex_rsa_get_len( (iotex_rsa_context *)ctx );
	return 0;
}

inline int iotex_rsa_gen_key( iotex_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         unsigned int nbits, int exponent )
{
    // return iotex_rsa_gen_key( (iotex_rsa_context *)ctx, f_rng, p_rng, nbits, exponent );
	return 0;
}

inline int iotex_rsa_check_pubkey( const iotex_rsa_context *ctx )
{
    // return iotex_rsa_check_pubkey( (iotex_rsa_context *)ctx );
	return 0;
}

inline int iotex_rsa_check_privkey( const iotex_rsa_context *ctx )
{
    // return iotex_rsa_check_privkey( (iotex_rsa_context *)ctx );
	return 0;
}

inline int iotex_rsa_check_pub_priv( const iotex_rsa_context *pub,
                                const iotex_rsa_context *prv )
{
    // return iotex_rsa_check_pub_priv( (iotex_rsa_context *)pub, (iotex_rsa_context *)prv );
	return 0;
}

inline int iotex_rsa_public( iotex_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    // return iotex_rsa_public( (iotex_rsa_context *)ctx,  input, output );
	return 0;
}

inline int iotex_rsa_private( iotex_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    // return iotex_rsa_private( (iotex_rsa_context *)ctx, f_rng, p_rng, input, output );
	return 0;
}

inline int iotex_rsa_pkcs1_encrypt( iotex_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    // return iotex_rsa_pkcs1_encrypt( (iotex_rsa_context *)ctx, f_rng, p_rng, ilen, input, output );
	return 0;
}

inline int iotex_rsa_rsaes_pkcs1_v15_encrypt( iotex_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    // return iotex_rsa_rsaes_pkcs1_v15_encrypt( (iotex_rsa_context *)ctx, f_rng, p_rng, ilen, input, output );
	return 0;
}

inline int iotex_rsa_rsaes_oaep_encrypt( iotex_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    // return iotex_rsa_rsaes_oaep_encrypt( (iotex_rsa_context *)ctx, f_rng, p_rng, label, label_len, ilen, input, output );
	return 0;
}

inline int iotex_rsa_pkcs1_decrypt( iotex_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len )
{
    // return iotex_rsa_pkcs1_decrypt( (iotex_rsa_context *)ctx, f_rng, p_rng, olen, input, output, output_max_len );
	return 0;
}

inline int iotex_rsa_rsaes_pkcs1_v15_decrypt( iotex_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len )
{
    // return iotex_rsa_rsaes_pkcs1_v15_decrypt( (iotex_rsa_context *)ctx, f_rng, p_rng, olen, input, output, output_max_len );
	return 0;
}

inline int iotex_rsa_rsaes_oaep_decrypt( iotex_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    // return iotex_rsa_rsaes_oaep_decrypt( (iotex_rsa_context *)ctx, f_rng, p_rng, label, label_len, olen, input, output, output_max_len );
	return 0;
}

inline int iotex_rsa_pkcs1_sign( iotex_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    iotex_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    // return iotex_rsa_pkcs1_sign( (iotex_rsa_context *)ctx, f_rng, p_rng, (iotex_md_type_t) md_alg, hashlen, hash, sig );
	return 0;
}

inline int iotex_rsa_rsassa_pkcs1_v15_sign( iotex_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               iotex_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    // return iotex_rsa_rsassa_pkcs1_v15_sign( (iotex_rsa_context *)ctx, f_rng, p_rng, (iotex_md_type_t) md_alg, hashlen, hash, sig );
	return 0;
}

inline int iotex_rsa_rsassa_pss_sign_ext( iotex_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         iotex_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         int saltlen,
                         unsigned char *sig )
{
    // return iotex_rsa_rsassa_pss_sign_ext( (iotex_rsa_context *)ctx, f_rng, p_rng, (iotex_md_type_t) md_alg, hashlen, hash, saltlen, sig );
	return 0;
}

inline int iotex_rsa_rsassa_pss_sign( iotex_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         iotex_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
    // return iotex_rsa_rsassa_pss_sign( (iotex_rsa_context *)ctx, f_rng, p_rng, (iotex_md_type_t) md_alg, hashlen, hash, sig );
	return 0;
}

inline int iotex_rsa_pkcs1_verify( iotex_rsa_context *ctx,
                      iotex_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig )
{
    // return iotex_rsa_pkcs1_verify( (iotex_rsa_context *)ctx, (iotex_md_type_t) md_alg, hashlen, hash, sig );
	return 0;
}

inline int iotex_rsa_rsassa_pkcs1_v15_verify( iotex_rsa_context *ctx,
                                 iotex_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig )
{
    // return iotex_rsa_rsassa_pkcs1_v15_verify( (iotex_rsa_context *)ctx, (iotex_md_type_t) md_alg, hashlen, hash, sig );
	return 0;
}

inline int iotex_rsa_rsassa_pss_verify( iotex_rsa_context *ctx,
                           iotex_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig )
{
    // return iotex_rsa_rsassa_pss_verify( (iotex_rsa_context *)ctx, (iotex_md_type_t) md_alg, hashlen, hash, sig );
	return 0;
}

inline int iotex_rsa_rsassa_pss_verify_ext( iotex_rsa_context *ctx,
                               iotex_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               iotex_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{
    // return iotex_rsa_rsassa_pss_verify_ext( (iotex_rsa_context *)ctx, (iotex_md_type_t) md_alg, hashlen, hash, (iotex_md_type_t) mgf1_hash_id, expected_salt_len, sig );
	return 0;
}

inline int iotex_rsa_copy( iotex_rsa_context *dst, const iotex_rsa_context *src )
{
    // return iotex_rsa_copy( (iotex_rsa_context *)dst, (iotex_rsa_context *)src );
	return 0;
}

inline void iotex_rsa_free( iotex_rsa_context *ctx )
{
    // iotex_rsa_free( (iotex_rsa_context *)ctx );
}

/****************************************************************/
/* BIGNUM */
/****************************************************************/
inline void iotex_mpi_init( iotex_mpi *X )
{
    // iotex_mpi_init( (iotex_mpi *)X );
}

inline int iotex_mpi_write_binary( const iotex_mpi *X, unsigned char *buf, size_t buflen )
{
    // return iotex_mpi_write_binary( (iotex_mpi *)X, buf, buflen );
	return 0;
}

inline int iotex_mpi_read_binary( iotex_mpi *X, const unsigned char *buf, size_t buflen )
{
    // return iotex_mpi_read_binary( (iotex_mpi *)X, buf, buflen );
	return 0;
}

inline void iotex_mpi_free( iotex_mpi *X )
{
    // iotex_mpi_free( (iotex_mpi *)X );
}

/****************************************************************/
/* ECP */
/****************************************************************/
static uint8_t public[2 * NUM_ECC_BYTES];
static uint8_t EdPublic[NUM_ECC_BYTES];

inline void iotex_ecp_keypair_init( iotex_ecp_keypair *key )
{
    (void)key;
}

inline int iotex_ecp_group_load( iotex_ecp_group *grp, iotex_ecp_group_id id )
{
    return 0;
}

inline int iotex_ecp_read_key( iotex_ecp_group_id grp_id, iotex_ecp_keypair *key,
                          const unsigned char *buf, size_t buflen )
{
#if ECDSA_VERIFY_USE_STR    
    unsigned char sebuf[65] = {0}; 
    int ret = -1;
    if (getPrikeyWithStr(sebuf))
        goto exit;

    ret =  iotex_mpi_read_string(&key->d, 16, sebuf);
    if(ret)
        goto exit;

    iotex_ecp_check_privkey( &key->grp, &key->d );
    if(ret)
        goto exit;

exit:
    return ret;
#else
    // return iotex_ecp_read_key( (iotex_ecp_group_id) grp_id, (iotex_ecp_keypair *)key, buf, buflen );
    return 0;
#endif

}

inline void iotex_ecp_keypair_free( iotex_ecp_keypair *key )
{
    
}

inline int iotex_ecp_point_read_binary( const iotex_ecp_group *grp,
                                   iotex_ecp_point *pt,
                                   const unsigned char *buf, size_t ilen )
{
    return 0;
}

inline int iotex_ecp_check_pubkey( const iotex_ecp_group *grp,
                              const iotex_ecp_point *pt )
{
    return 0;
}

inline int iotex_ecp_write_key( iotex_ecp_keypair *key,
                           unsigned char *buf, size_t buflen )
{    
    if(public[0] == 0)
        return IOTEX_ERR_ECP_INVALID_KEY;

    memcpy(buf, public, buflen);

    return 0;
}

inline int iotex_ecp_is_zero( iotex_ecp_point *pt )
{
    return 0;
}

inline int iotex_ecp_mul( iotex_ecp_group *grp, iotex_ecp_point *R,
             const iotex_mpi *m, const iotex_ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return 0;
}

inline int iotex_ecp_point_write_binary( const iotex_ecp_group *grp,
                                    const iotex_ecp_point *P,
                                    int format, size_t *olen,
                                    unsigned char *buf, size_t buflen )
{
    if(public[0] == 0)
        return IOTEX_ERR_ECP_INVALID_KEY;

    buf[0] = 0x04;
//    unsigned char *actbuf = buf + 1;
    memcpy(buf + 1, public, buflen - 1);

    *olen = buflen;

#if 0
    unsigned char *p = NULL;
    if( buflen >= (2 * NUM_ECC_BYTES + 1) )
    {
        buf[0] = 0x04;
        p = buf + 1;
    }
    else if( buflen == (2 * NUM_ECC_BYTES) )
    {
        p = buf;
    }
    else
        return PSA_ERROR_INVALID_ARGUMENT;
#endif

    return PSA_SUCCESS;    
}

#ifdef CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT
inline int iotex_ecp_gen_key( psa_key_type_t type, uint8_t *key_buffer, size_t key_buffer_size )
{
    uECC_Curve curve = uECC_secp256r1();

    if(key_buffer == NULL)
        return 1;

    switch (type)
    {
    case PSA_ECC_FAMILY_TWISTED_EDWARDS:
        return uECC_make_key_with_ed25519(EdPublic, key_buffer);
    case PSA_ECC_FAMILY_SECP_R1:
        curve = uECC_secp256r1();
        break;
    case PSA_ECC_FAMILY_SECP_K1:
        curve = uECC_secp256k1();
        break;
    default:
        break;
    }

    uECC_make_key(public, key_buffer, curve);

    return 0;
}
#endif

inline int iotex_ecp_calc_pub_key( psa_key_type_t type, uint8_t *key_buffer, size_t key_buffer_size )
{
    uECC_Curve curve = uECC_secp256r1();

    if(key_buffer == NULL)
        return 1;

    switch (type)
    {
    case PSA_ECC_FAMILY_TWISTED_EDWARDS:
        return uECC_compute_public_key_with_ed25519(key_buffer, EdPublic);
    case PSA_ECC_FAMILY_SECP_R1:
        curve = uECC_secp256r1();
        break;
    case PSA_ECC_FAMILY_SECP_K1:
        curve = uECC_secp256k1();
        break;
    default:
        break;
    }

    uECC_compute_public_key(key_buffer, public, curve);

    return 0;
}

inline int iotex_psa_ecp_export_key_from_raw_data(psa_key_type_t type, const uint8_t *key_buffer, uint8_t *data, size_t *data_length )
{
    uECC_Curve curve = uECC_secp256r1();

    if(key_buffer == NULL)
        return 1;

    switch (type)
    {
    case PSA_ECC_FAMILY_TWISTED_EDWARDS:
        uECC_compute_public_key_with_ed25519(key_buffer, data);
        *data_length = 32;

        return 0;
    case PSA_ECC_FAMILY_SECP_R1:
        curve = uECC_secp256r1();
        break;
    case PSA_ECC_FAMILY_SECP_K1:
        curve = uECC_secp256k1();
        break;
    default:
        break;
    }
    
    uECC_compute_public_key(key_buffer, data, curve);
    *data_length = 64;

    return 0;
}

/****************************************************************/
/* ECDSA */
/****************************************************************/

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
inline int iotex_ecdsa_sign( iotex_ecp_group *grp, iotex_mpi *r, iotex_mpi *s,
                const iotex_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    // return iotex_ecdsa_sign(grp, r, s, d, buf, blen, f_rng, p_rng);
	return 0;
}

inline int iotex_ecdsa_sign_det_ext( iotex_ecp_group *grp, iotex_mpi *r,
                            iotex_mpi *s, const iotex_mpi *d,
                            const unsigned char *buf, size_t blen,
                            iotex_md_type_t md_alg,
                            int (*f_rng_blind)(void *, unsigned char *, size_t),
                            void *p_rng_blind )
{
    // return iotex_ecdsa_sign_det_ext( (iotex_ecp_group *)grp, (iotex_mpi *)r, (iotex_mpi *)s, (iotex_mpi *)d, buf, blen, (iotex_md_type_t) md_alg, f_rng_blind, p_rng_blind );
	return 0;
}

inline int iotex_ecdsa_verify( iotex_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const iotex_ecp_point *Q, const iotex_mpi *r,
                          const iotex_mpi *s)
{
    // return iotex_ecdsa_verify( (iotex_ecp_group *)grp, buf, blen, (iotex_ecp_point *)Q, (iotex_mpi *)r, (iotex_mpi *)s);
	return 0;
}

#else
inline int iotex_ecdsa_sign( psa_key_type_t type, 
                            const uint8_t *key_buffer, size_t key_buffer_size, 
                            const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t *signature_length )
{
    const struct uECC_Curve_t * curve;
    int ret = 0;

    uECC_set_rng(&default_CSPRNG);

    switch( type )
    {
        case PSA_ECC_FAMILY_SECP_R1:

            curve = uECC_secp256r1();

            break;
        case PSA_ECC_FAMILY_SECP_K1:

            curve = uECC_secp256k1();

            break;
        default:
            return 1;
    }

    ret = uECC_sign(key_buffer, hash, hash_length, signature, curve);
    if ( ret )
        *signature_length = 64;
    else
        return PSA_ERROR_GENERIC_ERROR;

    return PSA_SUCCESS;
}

int iotex_eddsa_sign( psa_key_type_t type, 
                            const uint8_t *key_buffer, size_t key_buffer_size, 
                            const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t *signature_length )
{
    int ret = 0;

    uECC_set_rng(&default_CSPRNG);

    if (EdPublic[0])
        ret = uECC_ed25519_sign(key_buffer, EdPublic, hash, hash_length, signature);
    else
        ret = 0;

    if ( ret )
        *signature_length = 64;
    else
        return PSA_ERROR_GENERIC_ERROR;

    return PSA_SUCCESS;
}


int iotex_ecdsa_verify( psa_key_type_t type,
                          const uint8_t *key_buffer, size_t key_buffer_size,
                          const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_length )
{
    const struct uECC_Curve_t * curve;
    uint8_t public_key[2 * NUM_ECC_BYTES] = {0};
    int ret;

    switch( type )
    {
        case PSA_ECC_FAMILY_SECP_R1:

            curve = uECC_secp256r1();

            break;
        case PSA_ECC_FAMILY_SECP_K1:
    
            curve = uECC_secp256k1();

            break;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }     

    uECC_compute_public_key(key_buffer, public_key, curve);

    ret = uECC_verify(public_key, hash, hash_length, signature, curve);
    if ( 0 == ret )
        return PSA_ERROR_GENERIC_ERROR;

    return PSA_SUCCESS;
}

int iotex_eddsa_verify( psa_key_type_t type,
                          const uint8_t *key_buffer, size_t key_buffer_size,
                          const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_length )
{
    int ret;

    if (EdPublic[0])
        ret = uECC_ed25519_verify(EdPublic, hash, hash_length, signature);
    else
        ret = 0;

    if ( 0 == ret )
        return PSA_ERROR_GENERIC_ERROR;

    return PSA_SUCCESS;
}

#endif


psa_status_t iotex_key_agreement_ecdh( uint32_t curve,
                                        const uint8_t *key, size_t key_length, const uint8_t *peer_key, size_t peer_key_length,
                                        uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length)
{
    uECC_Curve crv = uECC_secp256r1();
    
    switch (curve) {
        case PSA_ECC_FAMILY_SECP_R1:
            crv = uECC_secp256r1();
            break;
        case PSA_ECC_FAMILY_SECP_K1:
            crv = uECC_secp256k1();
            break;    
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (!uECC_shared_secret(peer_key, key, shared_secret, crv)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    *shared_secret_length = NUM_ECC_BYTES;
    
    return PSA_SUCCESS;
}

/****************************************************************/
/* Random generation */
/****************************************************************/
iotex_psa_get_ts_func get_timestamp = NULL;

uint8_t default_entroy[] = {
			0xff, 0x0c, 0xdd, 0x55, 0x5c, 0x60, 0x46, 0x47, 0x60, 0xb2, 0x89, 0xb7,
			0xbc, 0x1f, 0x81, 0x1a, 0x41, 0xff, 0xf7, 0x2d, 0xe5, 0x90, 0x83, 0x85,
			0x8c, 0x02, 0x0a, 0x10, 0x53, 0xbd, 0xc7, 0x4a};

uint8_t default_entroy_reseed[] = {
			0x49, 0x3b, 0x64, 0x7f, 0xf0, 0xb3, 0xfa, 0xa2, 0x92, 0x1f, 0x12, 0xf8,
			0xf5, 0x7b, 0x91, 0x93, 0x29, 0xf2, 0xaf, 0x2f, 0xc1, 0xf1, 0x45, 0x76,
			0xd9, 0xdf, 0x2f, 0x8c, 0xc2, 0xad, 0xa7, 0xa6};            

void iotex_psa_set_timestamp(iotex_psa_get_ts_func func)
{
    get_timestamp = func;
}

#if !defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG)

struct iotex_hmac_prng_ctx {

	uint8_t entropyinputlen;
	uint8_t noncelen;
	uint8_t personalizationstringlen;
	uint8_t additionalinputlen;
	uint8_t returnedbitslen;
	uint8_t entropyinput[32];
	uint8_t nonce[16];
	uint8_t personalizationstring[32];
	uint8_t entropyinputreseed[32];
	uint8_t additionalinputreseed[32];

    struct tc_hmac_prng_struct h;

    iotex_psa_entroy_inject entroy_inject;

} iotex_hmac_prng_ctx = {0};

#endif

#if defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG)

psa_status_t iotex_psa_external_get_random(iotex_psa_external_random_context_t *context,
              uint8_t *output, size_t output_size, size_t *output_length)
{ 
    default_CSPRNG(output, output_size);

    *output_length = output_size;

    return( PSA_SUCCESS );
}
#else
int iotex_hardware_poll( void *data, unsigned char *output, size_t len, size_t *olen )
{
	return 0;
}

void iotex_psa_set_personalstring(uint8_t *string, size_t string_len)
{
    uint8_t personalizationstringlen = string_len;

    if( NULL == string || 0 == string_len)
        return;

    if(string_len > 32)
        personalizationstringlen = 32;

    memcpy(iotex_hmac_prng_ctx.personalizationstring, string, personalizationstringlen);
    iotex_hmac_prng_ctx.personalizationstringlen = personalizationstringlen;
}

void iotex_psa_set_entroy_inject_func(iotex_psa_entroy_inject entroy_inject)
{
    iotex_hmac_prng_ctx.entroy_inject = entroy_inject;
}

void iotex_entropy_init(iotex_entropy_context *ctx)
{
	uint8_t  seed_material[32 + 16 + 32] = {0};            /*entropyinput || nonce || personalizationstring */
	uint32_t seed_material_size = 0;
    uint32_t timestamp = 0;

	uint8_t *p = seed_material;

	memset(&iotex_hmac_prng_ctx.h, 0x0, sizeof(iotex_hmac_prng_ctx.h));

    if (iotex_hmac_prng_ctx.entroy_inject) {
        for (int i = 0; i < 32; i++)
            iotex_hmac_prng_ctx.entropyinput[i] = (uint8_t)iotex_hmac_prng_ctx.entroy_inject(255);

        iotex_hmac_prng_ctx.entropyinputlen = 32;     
    } else {
        memcpy(iotex_hmac_prng_ctx.entropyinput, default_entroy, 32);
        iotex_hmac_prng_ctx.entropyinputlen = 32;
    }

    if ( get_timestamp ) {

        timestamp = (uint32_t)get_timestamp();
        iotex_hmac_prng_ctx.noncelen = iotex_int_to_string(timestamp, (char *)iotex_hmac_prng_ctx.nonce);

    }

	if (iotex_hmac_prng_ctx.entropyinputlen > 0) {
		memcpy(p, iotex_hmac_prng_ctx.entropyinput, iotex_hmac_prng_ctx.entropyinputlen);
		p += iotex_hmac_prng_ctx.entropyinputlen;
	}

	if (iotex_hmac_prng_ctx.noncelen > 0) {
		memcpy(p, iotex_hmac_prng_ctx.nonce, iotex_hmac_prng_ctx.noncelen);
		p += iotex_hmac_prng_ctx.noncelen;
	}

	if (iotex_hmac_prng_ctx.personalizationstringlen > 0) {
		memcpy(p, iotex_hmac_prng_ctx.personalizationstring, iotex_hmac_prng_ctx.personalizationstringlen);
	}

	seed_material_size = iotex_hmac_prng_ctx.entropyinputlen + iotex_hmac_prng_ctx.noncelen + iotex_hmac_prng_ctx.personalizationstringlen;
	(void)tc_hmac_prng_init(&iotex_hmac_prng_ctx.h, seed_material, seed_material_size);

}

void iotex_entropy_free(iotex_entropy_context *ctx)
{

}

int iotex_hmac_drbg_seed( iotex_hmac_drbg_context *ctx,
                    const iotex_md_info_t * md_info,
                    int (*f_entropy)(void *, unsigned char *, size_t),
                    void *p_entropy,
                    const unsigned char *custom,
                    size_t len )
{
    int ret = tc_hmac_prng_reseed(&iotex_hmac_prng_ctx.h, default_entroy_reseed, 32, 0, 0);
    if (TC_CRYPTO_SUCCESS != ret)
        return PSA_ERROR_INVALID_ARGUMENT;
    
    return PSA_SUCCESS;
}

int iotex_hmac_drbg_reseed( iotex_hmac_drbg_context *ctx, const unsigned char *additional, size_t len )
{
    int ret = 0;

    if (iotex_hmac_prng_ctx.entroy_inject) {
        for (int i = 0; i < 32; i++)
            iotex_hmac_prng_ctx.entropyinputreseed[i] = (uint8_t)iotex_hmac_prng_ctx.entroy_inject(255);
    } else {
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }

    ret = tc_hmac_prng_reseed(&iotex_hmac_prng_ctx.h, iotex_hmac_prng_ctx.entropyinputreseed, iotex_hmac_prng_ctx.entropyinputlen, 0, 0);
    if (TC_CRYPTO_SUCCESS != ret)
        return PSA_ERROR_INVALID_ARGUMENT;
    
    return PSA_SUCCESS;
}

int iotex_entropy_func(void *data, unsigned char *output, size_t len)
{
    return 0;
}

void iotex_hmac_drbg_init( iotex_hmac_drbg_context *ctx )
{

}

int iotex_hmac_drbg_random( void *p_rng, unsigned char *output, size_t out_len )
{
    int ret = 0;

    ret = tc_hmac_prng_generate(output, out_len, &iotex_hmac_prng_ctx.h);
    switch (ret) {
        case TC_CRYPTO_SUCCESS:
            break;
        case TC_HMAC_PRNG_RESEED_REQ:
            break;
        case TC_CRYPTO_FAIL:
            break;     
    }

    return 0;
}

void iotex_hmac_drbg_free( iotex_hmac_drbg_context *ctx )
{

}
#endif /* !defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG) */


/****************************************************************/
/* Module setup */
/****************************************************************/


/****************************************************************/
/* Platform Util */
/****************************************************************/

#if !defined(IOTEX_PLATFORM_ZEROIZE_ALT)

static void * (* const volatile memset_func)( void *, int, size_t ) = memset;

void iotex_platform_zeroize( void *buf, size_t len )
{
    if( len > 0 )
        memset_func( buf, 0, len );
}
#endif /* IOTEX_PLATFORM_ZEROIZE_ALT */

#endif /* CONFIG_PSA_CRYPTO_BACKENDS_TINYCRYPT */
#endif /* IOTEX_PSA_CRYPTO_C */
