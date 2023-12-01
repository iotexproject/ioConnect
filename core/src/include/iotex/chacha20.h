#ifndef IOTEX_CHACHA20_H
#define IOTEX_CHACHA20_H

#include "include/iotex/build_info.h"

#include <stdint.h>
#include <stddef.h>

/** Invalid input parameter(s). */
#define IOTEX_ERR_CHACHA20_BAD_INPUT_DATA         -0x0051

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IOTEX_CHACHA20_ALT)

typedef struct iotex_chacha20_context
{
    uint32_t state[16];          /*! The state (before round operations). */
    uint8_t  keystream8[64];     /*! Leftover keystream bytes. */
    size_t keystream_bytes_used; /*! Number of keystream bytes already used. */
}
iotex_chacha20_context;

#else  /* IOTEX_CHACHA20_ALT */
#include "include/chacha20_alt.h"
#endif /* IOTEX_CHACHA20_ALT */

/**
 * \brief           This function initializes the specified ChaCha20 context.
 *
 *                  It must be the first API called before using
 *                  the context.
 *
 *                  It is usually followed by calls to
 *                  \c iotex_chacha20_setkey() and
 *                  \c iotex_chacha20_starts(), then one or more calls to
 *                  to \c iotex_chacha20_update(), and finally to
 *                  \c iotex_chacha20_free().
 *
 * \param ctx       The ChaCha20 context to initialize.
 *                  This must not be \c NULL.
 */
void iotex_chacha20_init( iotex_chacha20_context *ctx );

/**
 * \brief           This function releases and clears the specified
 *                  ChaCha20 context.
 *
 * \param ctx       The ChaCha20 context to clear. This may be \c NULL,
 *                  in which case this function is a no-op. If it is not
 *                  \c NULL, it must point to an initialized context.
 *
 */
void iotex_chacha20_free( iotex_chacha20_context *ctx );

/**
 * \brief           This function sets the encryption/decryption key.
 *
 * \note            After using this function, you must also call
 *                  \c iotex_chacha20_starts() to set a nonce before you
 *                  start encrypting/decrypting data with
 *                  \c iotex_chacha_update().
 *
 * \param ctx       The ChaCha20 context to which the key should be bound.
 *                  It must be initialized.
 * \param key       The encryption/decryption key. This must be \c 32 Bytes
 *                  in length.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_CHACHA20_BAD_INPUT_DATA if ctx or key is NULL.
 */
int iotex_chacha20_setkey( iotex_chacha20_context *ctx,
                             const unsigned char key[32] );

/**
 * \brief           This function sets the nonce and initial counter value.
 *
 * \note            A ChaCha20 context can be re-used with the same key by
 *                  calling this function to change the nonce.
 *
 * \warning         You must never use the same nonce twice with the same key.
 *                  This would void any confidentiality guarantees for the
 *                  messages encrypted with the same nonce and key.
 *
 * \param ctx       The ChaCha20 context to which the nonce should be bound.
 *                  It must be initialized and bound to a key.
 * \param nonce     The nonce. This must be \c 12 Bytes in size.
 * \param counter   The initial counter value. This is usually \c 0.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_CHACHA20_BAD_INPUT_DATA if ctx or nonce is
 *                  NULL.
 */
int iotex_chacha20_starts( iotex_chacha20_context* ctx,
                             const unsigned char nonce[12],
                             uint32_t counter );

/**
 * \brief           This function encrypts or decrypts data.
 *
 *                  Since ChaCha20 is a stream cipher, the same operation is
 *                  used for encrypting and decrypting data.
 *
 * \note            The \p input and \p output pointers must either be equal or
 *                  point to non-overlapping buffers.
 *
 * \note            \c iotex_chacha20_setkey() and
 *                  \c iotex_chacha20_starts() must be called at least once
 *                  to setup the context before this function can be called.
 *
 * \note            This function can be called multiple times in a row in
 *                  order to encrypt of decrypt data piecewise with the same
 *                  key and nonce.
 *
 * \param ctx       The ChaCha20 context to use for encryption or decryption.
 *                  It must be initialized and bound to a key and nonce.
 * \param size      The length of the input data in Bytes.
 * \param input     The buffer holding the input data.
 *                  This pointer can be \c NULL if `size == 0`.
 * \param output    The buffer holding the output data.
 *                  This must be able to hold \p size Bytes.
 *                  This pointer can be \c NULL if `size == 0`.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int iotex_chacha20_update( iotex_chacha20_context *ctx,
                             size_t size,
                             const unsigned char *input,
                             unsigned char *output );

/**
 * \brief           This function encrypts or decrypts data with ChaCha20 and
 *                  the given key and nonce.
 *
 *                  Since ChaCha20 is a stream cipher, the same operation is
 *                  used for encrypting and decrypting data.
 *
 * \warning         You must never use the same (key, nonce) pair more than
 *                  once. This would void any confidentiality guarantees for
 *                  the messages encrypted with the same nonce and key.
 *
 * \note            The \p input and \p output pointers must either be equal or
 *                  point to non-overlapping buffers.
 *
 * \param key       The encryption/decryption key.
 *                  This must be \c 32 Bytes in length.
 * \param nonce     The nonce. This must be \c 12 Bytes in size.
 * \param counter   The initial counter value. This is usually \c 0.
 * \param size      The length of the input data in Bytes.
 * \param input     The buffer holding the input data.
 *                  This pointer can be \c NULL if `size == 0`.
 * \param output    The buffer holding the output data.
 *                  This must be able to hold \p size Bytes.
 *                  This pointer can be \c NULL if `size == 0`.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int iotex_chacha20_crypt( const unsigned char key[32],
                            const unsigned char nonce[12],
                            uint32_t counter,
                            size_t size,
                            const unsigned char* input,
                            unsigned char* output );

#if defined(IOTEX_SELF_TEST)
/**
 * \brief           The ChaCha20 checkup routine.
 *
 * \return          \c 0 on success.
 * \return          \c 1 on failure.
 */
int iotex_chacha20_self_test( int verbose );
#endif /* IOTEX_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* IOTEX_CHACHA20_H */
