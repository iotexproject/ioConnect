#ifndef IOTEX_GCM_H
#define IOTEX_GCM_H

#include "include/iotex/build_info.h"

#include "include/iotex/cipher.h"

#include <stdint.h>

#define IOTEX_GCM_ENCRYPT     1
#define IOTEX_GCM_DECRYPT     0

/** Authenticated decryption failed. */
#define IOTEX_ERR_GCM_AUTH_FAILED                       -0x0012
/** Bad input parameters to function. */
#define IOTEX_ERR_GCM_BAD_INPUT                         -0x0014
/** An output buffer is too small. */
#define IOTEX_ERR_GCM_BUFFER_TOO_SMALL                  -0x0016

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IOTEX_GCM_ALT)

/**
 * \brief          The GCM context structure.
 */
typedef struct iotex_gcm_context
{
    iotex_cipher_context_t cipher_ctx;  /*!< The cipher context used. */
    uint64_t HL[16];                      /*!< Precalculated HTable low. */
    uint64_t HH[16];                      /*!< Precalculated HTable high. */
    uint64_t len;                         /*!< The total length of the encrypted data. */
    uint64_t add_len;                     /*!< The total length of the additional data. */
    unsigned char base_ectr[16];          /*!< The first ECTR for tag. */
    unsigned char y[16];                  /*!< The Y working value. */
    unsigned char buf[16];                /*!< The buf working value. */
    int mode;                             /*!< The operation to perform:
                                               #IOTEX_GCM_ENCRYPT or
                                               #IOTEX_GCM_DECRYPT. */
}
iotex_gcm_context;

#else  /* !IOTEX_GCM_ALT */
#include "include/gcm_alt.h"
#endif /* !IOTEX_GCM_ALT */

/**
 * \brief           This function initializes the specified GCM context,
 *                  to make references valid, and prepares the context
 *                  for iotex_gcm_setkey() or iotex_gcm_free().
 *
 *                  The function does not bind the GCM context to a particular
 *                  cipher, nor set the key. For this purpose, use
 *                  iotex_gcm_setkey().
 *
 * \param ctx       The GCM context to initialize. This must not be \c NULL.
 */
void iotex_gcm_init( iotex_gcm_context *ctx );

/**
 * \brief           This function associates a GCM context with a
 *                  cipher algorithm and a key.
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key. This must be a readable buffer of at
 *                  least \p keybits bits.
 * \param keybits   The key size in bits. Valid options are:
 *                  <ul><li>128 bits</li>
 *                  <li>192 bits</li>
 *                  <li>256 bits</li></ul>
 *
 * \return          \c 0 on success.
 * \return          A cipher-specific error code on failure.
 */
int iotex_gcm_setkey( iotex_gcm_context *ctx,
                        iotex_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits );

/**
 * \brief           This function performs GCM encryption or decryption of a buffer.
 *
 * \note            For encryption, the output buffer can be the same as the
 *                  input buffer. For decryption, the output buffer cannot be
 *                  the same as input buffer. If the buffers overlap, the output
 *                  buffer must trail at least 8 Bytes behind the input buffer.
 *
 * \warning         When this function performs a decryption, it outputs the
 *                  authentication tag and does not verify that the data is
 *                  authentic. You should use this function to perform encryption
 *                  only. For decryption, use iotex_gcm_auth_decrypt() instead.
 *
 * \param ctx       The GCM context to use for encryption or decryption. This
 *                  must be initialized.
 * \param mode      The operation to perform:
 *                  - #IOTEX_GCM_ENCRYPT to perform authenticated encryption.
 *                    The ciphertext is written to \p output and the
 *                    authentication tag is written to \p tag.
 *                  - #IOTEX_GCM_DECRYPT to perform decryption.
 *                    The plaintext is written to \p output and the
 *                    authentication tag is written to \p tag.
 *                    Note that this mode is not recommended, because it does
 *                    not verify the authenticity of the data. For this reason,
 *                    you should use iotex_gcm_auth_decrypt() instead of
 *                    calling this function in decryption mode.
 * \param length    The length of the input data, which is equal to the length
 *                  of the output data.
 * \param iv        The initialization vector. This must be a readable buffer of
 *                  at least \p iv_len Bytes.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data. This must be of at
 *                  least that size in Bytes.
 * \param add_len   The length of the additional data.
 * \param input     The buffer holding the input data. If \p length is greater
 *                  than zero, this must be a readable buffer of at least that
 *                  size in Bytes.
 * \param output    The buffer for holding the output data. If \p length is greater
 *                  than zero, this must be a writable buffer of at least that
 *                  size in Bytes.
 * \param tag_len   The length of the tag to generate.
 * \param tag       The buffer for holding the tag. This must be a writable
 *                  buffer of at least \p tag_len Bytes.
 *
 * \return          \c 0 if the encryption or decryption was performed
 *                  successfully. Note that in #IOTEX_GCM_DECRYPT mode,
 *                  this does not indicate that the data is authentic.
 * \return          #IOTEX_ERR_GCM_BAD_INPUT if the lengths or pointers are
 *                  not valid or a cipher-specific error code if the encryption
 *                  or decryption failed.
 */
int iotex_gcm_crypt_and_tag( iotex_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag );

/**
 * \brief           This function performs a GCM authenticated decryption of a
 *                  buffer.
 *
 * \note            For decryption, the output buffer cannot be the same as
 *                  input buffer. If the buffers overlap, the output buffer
 *                  must trail at least 8 Bytes behind the input buffer.
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param length    The length of the ciphertext to decrypt, which is also
 *                  the length of the decrypted plaintext.
 * \param iv        The initialization vector. This must be a readable buffer
 *                  of at least \p iv_len Bytes.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data. This must be of at
 *                  least that size in Bytes.
 * \param add_len   The length of the additional data.
 * \param tag       The buffer holding the tag to verify. This must be a
 *                  readable buffer of at least \p tag_len Bytes.
 * \param tag_len   The length of the tag to verify.
 * \param input     The buffer holding the ciphertext. If \p length is greater
 *                  than zero, this must be a readable buffer of at least that
 *                  size.
 * \param output    The buffer for holding the decrypted plaintext. If \p length
 *                  is greater than zero, this must be a writable buffer of at
 *                  least that size.
 *
 * \return          \c 0 if successful and authenticated.
 * \return          #IOTEX_ERR_GCM_AUTH_FAILED if the tag does not match.
 * \return          #IOTEX_ERR_GCM_BAD_INPUT if the lengths or pointers are
 *                  not valid or a cipher-specific error code if the decryption
 *                  failed.
 */
int iotex_gcm_auth_decrypt( iotex_gcm_context *ctx,
                      size_t length,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *tag,
                      size_t tag_len,
                      const unsigned char *input,
                      unsigned char *output );

/**
 * \brief           This function starts a GCM encryption or decryption
 *                  operation.
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param mode      The operation to perform: #IOTEX_GCM_ENCRYPT or
 *                  #IOTEX_GCM_DECRYPT.
 * \param iv        The initialization vector. This must be a readable buffer of
 *                  at least \p iv_len Bytes.
 * \param iv_len    The length of the IV.
 *
 * \return          \c 0 on success.
 */
int iotex_gcm_starts( iotex_gcm_context *ctx,
                        int mode,
                        const unsigned char *iv,
                        size_t iv_len );

/**
 * \brief           This function feeds an input buffer as associated data
 *                  (authenticated but not encrypted data) in a GCM
 *                  encryption or decryption operation.
 *
 *                  Call this function after iotex_gcm_starts() to pass
 *                  the associated data. If the associated data is empty,
 *                  you do not need to call this function. You may not
 *                  call this function after calling iotex_cipher_update().
 *
 * \param ctx       The GCM context. This must have been started with
 *                  iotex_gcm_starts() and must not have yet received
 *                  any input with iotex_gcm_update().
 * \param add       The buffer holding the additional data, or \c NULL
 *                  if \p add_len is \c 0.
 * \param add_len   The length of the additional data. If \c 0,
 *                  \p add may be \c NULL.
 *
 * \return          \c 0 on success.
 */
int iotex_gcm_update_ad( iotex_gcm_context *ctx,
                           const unsigned char *add,
                           size_t add_len );

/**
 * \brief           This function feeds an input buffer into an ongoing GCM
 *                  encryption or decryption operation.
 *
 *                  You may call this function zero, one or more times
 *                  to pass successive parts of the input: the plaintext to
 *                  encrypt, or the ciphertext (not including the tag) to
 *                  decrypt. After the last part of the input, call
 *                  iotex_gcm_finish().
 *
 *                  This function may produce output in one of the following
 *                  ways:
 *                  - Immediate output: the output length is always equal
 *                    to the input length.
 *                  - Buffered output: the output consists of a whole number
 *                    of 16-byte blocks. If the total input length so far
 *                    (not including associated data) is 16 \* *B* + *A*
 *                    with *A* < 16 then the total output length is 16 \* *B*.
 *
 *                  In particular:
 *                  - It is always correct to call this function with
 *                    \p output_size >= \p input_length + 15.
 *                  - If \p input_length is a multiple of 16 for all the calls
 *                    to this function during an operation, then it is
 *                    correct to use \p output_size = \p input_length.
 *
 * \note            For decryption, the output buffer cannot be the same as
 *                  input buffer. If the buffers overlap, the output buffer
 *                  must trail at least 8 Bytes behind the input buffer.
 *
 * \param ctx           The GCM context. This must be initialized.
 * \param input         The buffer holding the input data. If \p input_length
 *                      is greater than zero, this must be a readable buffer
 *                      of at least \p input_length bytes.
 * \param input_length  The length of the input data in bytes.
 * \param output        The buffer for the output data. If \p output_size
 *                      is greater than zero, this must be a writable buffer of
 *                      of at least \p output_size bytes.
 * \param output_size   The size of the output buffer in bytes.
 *                      See the function description regarding the output size.
 * \param output_length On success, \p *output_length contains the actual
 *                      length of the output written in \p output.
 *                      On failure, the content of \p *output_length is
 *                      unspecified.
 *
 * \return         \c 0 on success.
 * \return         #IOTEX_ERR_GCM_BAD_INPUT on failure:
 *                 total input length too long,
 *                 unsupported input/output buffer overlap detected,
 *                 or \p output_size too small.
 */
int iotex_gcm_update( iotex_gcm_context *ctx,
                        const unsigned char *input, size_t input_length,
                        unsigned char *output, size_t output_size,
                        size_t *output_length );

/**
 * \brief           This function finishes the GCM operation and generates
 *                  the authentication tag.
 *
 *                  It wraps up the GCM stream, and generates the
 *                  tag. The tag can have a maximum length of 16 Bytes.
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param tag       The buffer for holding the tag. This must be a writable
 *                  buffer of at least \p tag_len Bytes.
 * \param tag_len   The length of the tag to generate. This must be at least
 *                  four.
 * \param output    The buffer for the final output.
 *                  If \p output_size is nonzero, this must be a writable
 *                  buffer of at least \p output_size bytes.
 * \param output_size  The size of the \p output buffer in bytes.
 *                  This must be large enough for the output that
 *                  iotex_gcm_update() has not produced. In particular:
 *                  - If iotex_gcm_update() produces immediate output,
 *                    or if the total input size is a multiple of \c 16,
 *                    then iotex_gcm_finish() never produces any output,
 *                    so \p output_size can be \c 0.
 *                  - \p output_size never needs to be more than \c 15.
 * \param output_length On success, \p *output_length contains the actual
 *                      length of the output written in \p output.
 *                      On failure, the content of \p *output_length is
 *                      unspecified.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_GCM_BAD_INPUT on failure:
 *                  invalid value of \p tag_len,
 *                  or \p output_size too small.
 */
int iotex_gcm_finish( iotex_gcm_context *ctx,
                        unsigned char *output, size_t output_size,
                        size_t *output_length,
                        unsigned char *tag, size_t tag_len );

/**
 * \brief           This function clears a GCM context and the underlying
 *                  cipher sub-context.
 *
 * \param ctx       The GCM context to clear. If this is \c NULL, the call has
 *                  no effect. Otherwise, this must be initialized.
 */
void iotex_gcm_free( iotex_gcm_context *ctx );

#if defined(IOTEX_SELF_TEST)

/**
 * \brief          The GCM checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int iotex_gcm_self_test( int verbose );

#endif /* IOTEX_SELF_TEST */

#ifdef __cplusplus
}
#endif


#endif /* gcm.h */
