#ifndef IOTEX_MD_H
#define IOTEX_MD_H

#include <stddef.h>

#include "include/iotex/build_info.h"
#include "include/iotex/platform_util.h"

/** The selected feature is not available. */
#define IOTEX_ERR_MD_FEATURE_UNAVAILABLE                -0x5080
/** Bad input parameters to function. */
#define IOTEX_ERR_MD_BAD_INPUT_DATA                     -0x5100
/** Failed to allocate memory. */
#define IOTEX_ERR_MD_ALLOC_FAILED                       -0x5180
/** Opening or reading of file failed. */
#define IOTEX_ERR_MD_FILE_IO_ERROR                      -0x5200

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief     Supported message digests.
 *
 * \warning   MD5 and SHA-1 are considered weak message digests and
 *            their use constitutes a security risk. We recommend considering
 *            stronger message digests instead.
 *
 */
typedef enum {
    IOTEX_MD_NONE=0,    /**< None. */
    IOTEX_MD_MD5,       /**< The MD5 message digest. */
    IOTEX_MD_SHA1,      /**< The SHA-1 message digest. */
    IOTEX_MD_SHA224,    /**< The SHA-224 message digest. */
    IOTEX_MD_SHA256,    /**< The SHA-256 message digest. */
    IOTEX_MD_SHA384,    /**< The SHA-384 message digest. */
    IOTEX_MD_SHA512,    /**< The SHA-512 message digest. */
    IOTEX_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
} iotex_md_type_t;

#if defined(IOTEX_SHA512_C)
#define IOTEX_MD_MAX_SIZE         64  /* longest known is SHA512 */
#else
#define IOTEX_MD_MAX_SIZE         32  /* longest known is SHA256 or less */
#endif

#if defined(IOTEX_SHA512_C)
#define IOTEX_MD_MAX_BLOCK_SIZE         128
#else
#define IOTEX_MD_MAX_BLOCK_SIZE         64
#endif

/**
 * Opaque struct.
 *
 * Constructed using either #iotex_md_info_from_string or
 * #iotex_md_info_from_type.
 *
 * Fields can be accessed with #iotex_md_get_size,
 * #iotex_md_get_type and #iotex_md_get_name.
 */
/* Defined internally in library/md_wrap.h. */
typedef struct iotex_md_info_t iotex_md_info_t;

/**
 * The generic message-digest context.
 */
typedef struct iotex_md_context_t
{
    /** Information about the associated message digest. */
    const iotex_md_info_t *md_info;

    /** The digest-specific context. */
    void *md_ctx;

    /** The HMAC part of the context. */
    void *hmac_ctx;
} iotex_md_context_t;

/**
 * \brief           This function returns the list of digests supported by the
 *                  generic digest module.
 *
 * \note            The list starts with the strongest available hashes.
 *
 * \return          A statically allocated array of digests. Each element
 *                  in the returned list is an integer belonging to the
 *                  message-digest enumeration #iotex_md_type_t.
 *                  The last entry is 0.
 */
const int *iotex_md_list( void );

/**
 * \brief           This function returns the message-digest information
 *                  associated with the given digest name.
 *
 * \param md_name   The name of the digest to search for.
 *
 * \return          The message-digest information associated with \p md_name.
 * \return          NULL if the associated message-digest information is not found.
 */
const iotex_md_info_t *iotex_md_info_from_string( const char *md_name );

/**
 * \brief           This function returns the message-digest information
 *                  associated with the given digest type.
 *
 * \param md_type   The type of digest to search for.
 *
 * \return          The message-digest information associated with \p md_type.
 * \return          NULL if the associated message-digest information is not found.
 */
const iotex_md_info_t *iotex_md_info_from_type( iotex_md_type_t md_type );

/**
 * \brief           This function returns the message-digest information
 *                  from the given context.
 *
 * \param ctx       The context from which to extract the information.
 *                  This must be initialized (or \c NULL).
 *
 * \return          The message-digest information associated with \p ctx.
 * \return          \c NULL if \p ctx is \c NULL.
 */
const iotex_md_info_t *iotex_md_info_from_ctx(
                                        const iotex_md_context_t *ctx );

/**
 * \brief           This function initializes a message-digest context without
 *                  binding it to a particular message-digest algorithm.
 *
 *                  This function should always be called first. It prepares the
 *                  context for iotex_md_setup() for binding it to a
 *                  message-digest algorithm.
 */
void iotex_md_init( iotex_md_context_t *ctx );

/**
 * \brief           This function clears the internal structure of \p ctx and
 *                  frees any embedded internal structure, but does not free
 *                  \p ctx itself.
 *
 *                  If you have called iotex_md_setup() on \p ctx, you must
 *                  call iotex_md_free() when you are no longer using the
 *                  context.
 *                  Calling this function if you have previously
 *                  called iotex_md_init() and nothing else is optional.
 *                  You must not call this function if you have not called
 *                  iotex_md_init().
 */
void iotex_md_free( iotex_md_context_t *ctx );


/**
 * \brief           This function selects the message digest algorithm to use,
 *                  and allocates internal structures.
 *
 *                  It should be called after iotex_md_init() or
 *                  iotex_md_free(). Makes it necessary to call
 *                  iotex_md_free() later.
 *
 * \param ctx       The context to set up.
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 * \param hmac      Defines if HMAC is used. 0: HMAC is not used (saves some memory),
 *                  or non-zero: HMAC is used with this context.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 * \return          #IOTEX_ERR_MD_ALLOC_FAILED on memory-allocation failure.
 */
int iotex_md_setup( iotex_md_context_t *ctx, const iotex_md_info_t *md_info, int hmac );

/**
 * \brief           This function clones the state of an message-digest
 *                  context.
 *
 * \note            You must call iotex_md_setup() on \c dst before calling
 *                  this function.
 *
 * \note            The two contexts must have the same type,
 *                  for example, both are SHA-256.
 *
 * \warning         This function clones the message-digest state, not the
 *                  HMAC state.
 *
 * \param dst       The destination context.
 * \param src       The context to be cloned.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification failure.
 */
int iotex_md_clone( iotex_md_context_t *dst,
                      const iotex_md_context_t *src );

/**
 * \brief           This function extracts the message-digest size from the
 *                  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 *
 * \return          The size of the message-digest output in Bytes.
 */
unsigned char iotex_md_get_size( const iotex_md_info_t *md_info );

/**
 * \brief           This function extracts the message-digest type from the
 *                  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 *
 * \return          The type of the message digest.
 */
iotex_md_type_t iotex_md_get_type( const iotex_md_info_t *md_info );

/**
 * \brief           This function extracts the message-digest name from the
 *                  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 *
 * \return          The name of the message digest.
 */
const char *iotex_md_get_name( const iotex_md_info_t *md_info );

/**
 * \brief           This function starts a message-digest computation.
 *
 *                  You must call this function after setting up the context
 *                  with iotex_md_setup(), and before passing data with
 *                  iotex_md_update().
 *
 * \param ctx       The generic message-digest context.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int iotex_md_starts( iotex_md_context_t *ctx );

/**
 * \brief           This function feeds an input buffer into an ongoing
 *                  message-digest computation.
 *
 *                  You must call iotex_md_starts() before calling this
 *                  function. You may call this function multiple times.
 *                  Afterwards, call iotex_md_finish().
 *
 * \param ctx       The generic message-digest context.
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int iotex_md_update( iotex_md_context_t *ctx, const unsigned char *input, size_t ilen );

/**
 * \brief           This function finishes the digest operation,
 *                  and writes the result to the output buffer.
 *
 *                  Call this function after a call to iotex_md_starts(),
 *                  followed by any number of calls to iotex_md_update().
 *                  Afterwards, you may either clear the context with
 *                  iotex_md_free(), or call iotex_md_starts() to reuse
 *                  the context for another digest operation with the same
 *                  algorithm.
 *
 * \param ctx       The generic message-digest context.
 * \param output    The buffer for the generic message-digest checksum result.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int iotex_md_finish( iotex_md_context_t *ctx, unsigned char *output );

/**
 * \brief          This function calculates the message-digest of a buffer,
 *                 with respect to a configurable message-digest algorithm
 *                 in a single call.
 *
 *                 The result is calculated as
 *                 Output = message_digest(input buffer).
 *
 * \param md_info  The information structure of the message-digest algorithm
 *                 to use.
 * \param input    The buffer holding the data.
 * \param ilen     The length of the input data.
 * \param output   The generic message-digest checksum result.
 *
 * \return         \c 0 on success.
 * \return         #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                 failure.
 */
int iotex_md( const iotex_md_info_t *md_info, const unsigned char *input, size_t ilen,
        unsigned char *output );

#if defined(IOTEX_FS_IO)
/**
 * \brief          This function calculates the message-digest checksum
 *                 result of the contents of the provided file.
 *
 *                 The result is calculated as
 *                 Output = message_digest(file contents).
 *
 * \param md_info  The information structure of the message-digest algorithm
 *                 to use.
 * \param path     The input file name.
 * \param output   The generic message-digest checksum result.
 *
 * \return         \c 0 on success.
 * \return         #IOTEX_ERR_MD_FILE_IO_ERROR on an I/O error accessing
 *                 the file pointed by \p path.
 * \return         #IOTEX_ERR_MD_BAD_INPUT_DATA if \p md_info was NULL.
 */
int iotex_md_file( const iotex_md_info_t *md_info, const char *path,
                     unsigned char *output );
#endif /* IOTEX_FS_IO */

/**
 * \brief           This function sets the HMAC key and prepares to
 *                  authenticate a new message.
 *
 *                  Call this function after iotex_md_setup(), to use
 *                  the MD context for an HMAC calculation, then call
 *                  iotex_md_hmac_update() to provide the input data, and
 *                  iotex_md_hmac_finish() to get the HMAC value.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param key       The HMAC secret key.
 * \param keylen    The length of the HMAC key in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int iotex_md_hmac_starts( iotex_md_context_t *ctx, const unsigned char *key,
                    size_t keylen );

/**
 * \brief           This function feeds an input buffer into an ongoing HMAC
 *                  computation.
 *
 *                  Call iotex_md_hmac_starts() or iotex_md_hmac_reset()
 *                  before calling this function.
 *                  You may call this function multiple times to pass the
 *                  input piecewise.
 *                  Afterwards, call iotex_md_hmac_finish().
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int iotex_md_hmac_update( iotex_md_context_t *ctx, const unsigned char *input,
                    size_t ilen );

/**
 * \brief           This function finishes the HMAC operation, and writes
 *                  the result to the output buffer.
 *
 *                  Call this function after iotex_md_hmac_starts() and
 *                  iotex_md_hmac_update() to get the HMAC value. Afterwards
 *                  you may either call iotex_md_free() to clear the context,
 *                  or call iotex_md_hmac_reset() to reuse the context with
 *                  the same HMAC key.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param output    The generic HMAC checksum result.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int iotex_md_hmac_finish( iotex_md_context_t *ctx, unsigned char *output);

/**
 * \brief           This function prepares to authenticate a new message with
 *                  the same key as the previous HMAC operation.
 *
 *                  You may call this function after iotex_md_hmac_finish().
 *                  Afterwards call iotex_md_hmac_update() to pass the new
 *                  input.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int iotex_md_hmac_reset( iotex_md_context_t *ctx );

/**
 * \brief          This function calculates the full generic HMAC
 *                 on the input buffer with the provided key.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The HMAC result is calculated as
 *                 output = generic HMAC(hmac key, input buffer).
 *
 * \param md_info  The information structure of the message-digest algorithm
 *                 to use.
 * \param key      The HMAC secret key.
 * \param keylen   The length of the HMAC secret key in Bytes.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The generic HMAC result.
 *
 * \return         \c 0 on success.
 * \return         #IOTEX_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                 failure.
 */
int iotex_md_hmac( const iotex_md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output );

/* Internal use */
int iotex_md_process( iotex_md_context_t *ctx, const unsigned char *data );

#ifdef __cplusplus
}
#endif

#endif /* IOTEX_MD_H */
