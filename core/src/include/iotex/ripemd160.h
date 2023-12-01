#ifndef IOTEX_RIPEMD160_H
#define IOTEX_RIPEMD160_H

#include "include/iotex/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IOTEX_RIPEMD160_ALT)
// Regular implementation
//

/**
 * \brief          RIPEMD-160 context structure
 */
typedef struct iotex_ripemd160_context
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
iotex_ripemd160_context;

#else  /* IOTEX_RIPEMD160_ALT */
#include "include/ripemd160_alt.h"
#endif /* IOTEX_RIPEMD160_ALT */

/**
 * \brief          Initialize RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be initialized
 */
void iotex_ripemd160_init( iotex_ripemd160_context *ctx );

/**
 * \brief          Clear RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be cleared
 */
void iotex_ripemd160_free( iotex_ripemd160_context *ctx );

/**
 * \brief          Clone (the state of) an RIPEMD-160 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void iotex_ripemd160_clone( iotex_ripemd160_context *dst,
                        const iotex_ripemd160_context *src );

/**
 * \brief          RIPEMD-160 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 */
int iotex_ripemd160_starts( iotex_ripemd160_context *ctx );

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 */
int iotex_ripemd160_update( iotex_ripemd160_context *ctx,
                              const unsigned char *input,
                              size_t ilen );

/**
 * \brief          RIPEMD-160 final digest
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int iotex_ripemd160_finish( iotex_ripemd160_context *ctx,
                              unsigned char output[20] );

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 */
int iotex_internal_ripemd160_process( iotex_ripemd160_context *ctx,
                                        const unsigned char data[64] );

/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int iotex_ripemd160( const unsigned char *input,
                       size_t ilen,
                       unsigned char output[20] );

#if defined(IOTEX_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int iotex_ripemd160_self_test( int verbose );

#endif /* IOTEX_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* iotex_ripemd160.h */
