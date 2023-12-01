#ifndef IOTEX_POLY1305_H
#define IOTEX_POLY1305_H

#include "include/iotex/build_info.h"

#include <stdint.h>
#include <stddef.h>

/** Invalid input parameter(s). */
#define IOTEX_ERR_POLY1305_BAD_INPUT_DATA         -0x0057

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IOTEX_POLY1305_ALT)

typedef struct iotex_poly1305_context
{
    uint32_t r[4];      /** The value for 'r' (low 128 bits of the key). */
    uint32_t s[4];      /** The value for 's' (high 128 bits of the key). */
    uint32_t acc[5];    /** The accumulator number. */
    uint8_t queue[16];  /** The current partial block of data. */
    size_t queue_len;   /** The number of bytes stored in 'queue'. */
}
iotex_poly1305_context;

#else  /* IOTEX_POLY1305_ALT */
#include "include/poly1305_alt.h"
#endif /* IOTEX_POLY1305_ALT */

/**
 * \brief           This function initializes the specified Poly1305 context.
 *
 *                  It must be the first API called before using
 *                  the context.
 *
 *                  It is usually followed by a call to
 *                  \c iotex_poly1305_starts(), then one or more calls to
 *                  \c iotex_poly1305_update(), then one call to
 *                  \c iotex_poly1305_finish(), then finally
 *                  \c iotex_poly1305_free().
 *
 * \param ctx       The Poly1305 context to initialize. This must
 *                  not be \c NULL.
 */
void iotex_poly1305_init( iotex_poly1305_context *ctx );

/**
 * \brief           This function releases and clears the specified
 *                  Poly1305 context.
 *
 * \param ctx       The Poly1305 context to clear. This may be \c NULL, in which
 *                  case this function is a no-op. If it is not \c NULL, it must
 *                  point to an initialized Poly1305 context.
 */
void iotex_poly1305_free( iotex_poly1305_context *ctx );

/**
 * \brief           This function sets the one-time authentication key.
 *
 * \warning         The key must be unique and unpredictable for each
 *                  invocation of Poly1305.
 *
 * \param ctx       The Poly1305 context to which the key should be bound.
 *                  This must be initialized.
 * \param key       The buffer containing the \c 32 Byte (\c 256 Bit) key.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int iotex_poly1305_starts( iotex_poly1305_context *ctx,
                             const unsigned char key[32] );

/**
 * \brief           This functions feeds an input buffer into an ongoing
 *                  Poly1305 computation.
 *
 *                  It is called between \c iotex_cipher_poly1305_starts() and
 *                  \c iotex_cipher_poly1305_finish().
 *                  It can be called repeatedly to process a stream of data.
 *
 * \param ctx       The Poly1305 context to use for the Poly1305 operation.
 *                  This must be initialized and bound to a key.
 * \param ilen      The length of the input data in Bytes.
 *                  Any value is accepted.
 * \param input     The buffer holding the input data.
 *                  This pointer can be \c NULL if `ilen == 0`.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int iotex_poly1305_update( iotex_poly1305_context *ctx,
                             const unsigned char *input,
                             size_t ilen );

/**
 * \brief           This function generates the Poly1305 Message
 *                  Authentication Code (MAC).
 *
 * \param ctx       The Poly1305 context to use for the Poly1305 operation.
 *                  This must be initialized and bound to a key.
 * \param mac       The buffer to where the MAC is written. This must
 *                  be a writable buffer of length \c 16 Bytes.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int iotex_poly1305_finish( iotex_poly1305_context *ctx,
                             unsigned char mac[16] );

/**
 * \brief           This function calculates the Poly1305 MAC of the input
 *                  buffer with the provided key.
 *
 * \warning         The key must be unique and unpredictable for each
 *                  invocation of Poly1305.
 *
 * \param key       The buffer containing the \c 32 Byte (\c 256 Bit) key.
 * \param ilen      The length of the input data in Bytes.
 *                  Any value is accepted.
 * \param input     The buffer holding the input data.
 *                  This pointer can be \c NULL if `ilen == 0`.
 * \param mac       The buffer to where the MAC is written. This must be
 *                  a writable buffer of length \c 16 Bytes.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int iotex_poly1305_mac( const unsigned char key[32],
                          const unsigned char *input,
                          size_t ilen,
                          unsigned char mac[16] );

#if defined(IOTEX_SELF_TEST)
/**
 * \brief           The Poly1305 checkup routine.
 *
 * \return          \c 0 on success.
 * \return          \c 1 on failure.
 */
int iotex_poly1305_self_test( int verbose );
#endif /* IOTEX_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* IOTEX_POLY1305_H */
