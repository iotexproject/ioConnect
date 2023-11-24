#ifndef IOTEX_SHA1_H
#define IOTEX_SHA1_H

#include "include/iotex/build_info.h"

#include <stddef.h>
#include <stdint.h>

/** SHA-1 input data was malformed. */
#define IOTEX_ERR_SHA1_BAD_INPUT_DATA                   -0x0073

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IOTEX_SHA1_ALT)
// Regular implementation
//

/**
 * \brief          The SHA-1 context structure.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
typedef struct iotex_sha1_context
{
    uint32_t total[2];          /*!< The number of Bytes processed.  */
    uint32_t state[5];          /*!< The intermediate digest state.  */
    unsigned char buffer[64];   /*!< The data block being processed. */
}
iotex_sha1_context;

#else  /* IOTEX_SHA1_ALT */
#include "include/sha1_alt.h"
#endif /* IOTEX_SHA1_ALT */

/**
 * \brief          This function initializes a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to initialize.
 *                 This must not be \c NULL.
 *
 */
void iotex_sha1_init( iotex_sha1_context *ctx );

/**
 * \brief          This function clears a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to clear. This may be \c NULL,
 *                 in which case this function does nothing. If it is
 *                 not \c NULL, it must point to an initialized
 *                 SHA-1 context.
 *
 */
void iotex_sha1_free( iotex_sha1_context *ctx );

/**
 * \brief          This function clones the state of a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param dst      The SHA-1 context to clone to. This must be initialized.
 * \param src      The SHA-1 context to clone from. This must be initialized.
 *
 */
void iotex_sha1_clone( iotex_sha1_context *dst,
                         const iotex_sha1_context *src );

/**
 * \brief          This function starts a SHA-1 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to initialize. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
int iotex_sha1_starts( iotex_sha1_context *ctx );

/**
 * \brief          This function feeds an input buffer into an ongoing SHA-1
 *                 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the input data.
 *                 This must be a readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data \p input in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int iotex_sha1_update( iotex_sha1_context *ctx,
                         const unsigned char *input,
                         size_t ilen );

/**
 * \brief          This function finishes the SHA-1 operation, and writes
 *                 the result to the output buffer.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to use. This must be initialized and
 *                 have a hash operation started.
 * \param output   The SHA-1 checksum result. This must be a writable
 *                 buffer of length \c 20 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int iotex_sha1_finish( iotex_sha1_context *ctx,
                         unsigned char output[20] );

/**
 * \brief          SHA-1 process data block (internal use only).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to use. This must be initialized.
 * \param data     The data block being processed. This must be a
 *                 readable buffer of length \c 64 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
int iotex_internal_sha1_process( iotex_sha1_context *ctx,
                                   const unsigned char data[64] );

/**
 * \brief          This function calculates the SHA-1 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-1 result is calculated as
 *                 output = SHA-1(input buffer).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param input    The buffer holding the input data.
 *                 This must be a readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data \p input in Bytes.
 * \param output   The SHA-1 checksum result.
 *                 This must be a writable buffer of length \c 20 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
int iotex_sha1( const unsigned char *input,
                  size_t ilen,
                  unsigned char output[20] );

#if defined(IOTEX_SELF_TEST)

/**
 * \brief          The SHA-1 checkup routine.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 *
 */
int iotex_sha1_self_test( int verbose );

#endif /* IOTEX_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* iotex_sha1.h */
