#ifndef IOTEX_CTR_DRBG_H
#define IOTEX_CTR_DRBG_H

#include "include/iotex/build_info.h"

#include "include/backends/tinycryt/aes.h"

#if defined(IOTEX_THREADING_C)
#include "include/threading.h"
#endif

/** The entropy source failed. */
#define IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED        -0x0034
/** The requested random buffer length is too big. */
#define IOTEX_ERR_CTR_DRBG_REQUEST_TOO_BIG              -0x0036
/** The input (entropy + additional data) is too large. */
#define IOTEX_ERR_CTR_DRBG_INPUT_TOO_BIG                -0x0038
/** Read or write error in file. */
#define IOTEX_ERR_CTR_DRBG_FILE_IO_ERROR                -0x003A

#define IOTEX_CTR_DRBG_BLOCKSIZE          16 /**< The block size used by the cipher. */

#if defined(IOTEX_CTR_DRBG_USE_128_BIT_KEY)
#define IOTEX_CTR_DRBG_KEYSIZE            16
/**< The key size in bytes used by the cipher.
 *
 * Compile-time choice: 16 bytes (128 bits)
 * because #IOTEX_CTR_DRBG_USE_128_BIT_KEY is enabled.
 */
#else
#define IOTEX_CTR_DRBG_KEYSIZE            32
/**< The key size in bytes used by the cipher.
 *
 * Compile-time choice: 32 bytes (256 bits)
 * because \c IOTEX_CTR_DRBG_USE_128_BIT_KEY is disabled.
 */
#endif

#define IOTEX_CTR_DRBG_KEYBITS            ( IOTEX_CTR_DRBG_KEYSIZE * 8 ) /**< The key size for the DRBG operation, in bits. */
#define IOTEX_CTR_DRBG_SEEDLEN            ( IOTEX_CTR_DRBG_KEYSIZE + IOTEX_CTR_DRBG_BLOCKSIZE ) /**< The seed length, calculated as (counter + AES key). */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in iotex_config.h or define them using the compiler command
 * line.
 * \{
 */

/** \def IOTEX_CTR_DRBG_ENTROPY_LEN
 *
 * \brief The amount of entropy used per seed by default, in bytes.
 */
#if !defined(IOTEX_CTR_DRBG_ENTROPY_LEN)
#if defined(IOTEX_SHA512_C) && !defined(IOTEX_ENTROPY_FORCE_SHA256)
/** This is 48 bytes because the entropy module uses SHA-512
 * (\c IOTEX_ENTROPY_FORCE_SHA256 is disabled).
 */
#define IOTEX_CTR_DRBG_ENTROPY_LEN        48

#else /* defined(IOTEX_SHA512_C) && !defined(IOTEX_ENTROPY_FORCE_SHA256) */

/** This is 32 bytes because the entropy module uses SHA-256
 * (the SHA512 module is disabled or
 * \c IOTEX_ENTROPY_FORCE_SHA256 is enabled).
 */
#if !defined(IOTEX_CTR_DRBG_USE_128_BIT_KEY)
/** \warning To achieve a 256-bit security strength, you must pass a nonce
 *           to iotex_ctr_drbg_seed().
 */
#endif /* !defined(IOTEX_CTR_DRBG_USE_128_BIT_KEY) */
#define IOTEX_CTR_DRBG_ENTROPY_LEN        32
#endif /* defined(IOTEX_SHA512_C) && !defined(IOTEX_ENTROPY_FORCE_SHA256) */
#endif /* !defined(IOTEX_CTR_DRBG_ENTROPY_LEN) */

#if !defined(IOTEX_CTR_DRBG_RESEED_INTERVAL)
#define IOTEX_CTR_DRBG_RESEED_INTERVAL    10000
/**< The interval before reseed is performed by default. */
#endif

#if !defined(IOTEX_CTR_DRBG_MAX_INPUT)
#define IOTEX_CTR_DRBG_MAX_INPUT          256
/**< The maximum number of additional input Bytes. */
#endif

#if !defined(IOTEX_CTR_DRBG_MAX_REQUEST)
#define IOTEX_CTR_DRBG_MAX_REQUEST        1024
/**< The maximum number of requested Bytes per call. */
#endif

#if !defined(IOTEX_CTR_DRBG_MAX_SEED_INPUT)
#define IOTEX_CTR_DRBG_MAX_SEED_INPUT     384
/**< The maximum size of seed or reseed buffer in bytes. */
#endif

/** \} name SECTION: Module settings */

#define IOTEX_CTR_DRBG_PR_OFF             0
/**< Prediction resistance is disabled. */
#define IOTEX_CTR_DRBG_PR_ON              1
/**< Prediction resistance is enabled. */

#ifdef __cplusplus
extern "C" {
#endif

#if IOTEX_CTR_DRBG_ENTROPY_LEN >= IOTEX_CTR_DRBG_KEYSIZE * 3 / 2
/** The default length of the nonce read from the entropy source.
 *
 * This is \c 0 because a single read from the entropy source is sufficient
 * to include a nonce.
 * See the documentation of iotex_ctr_drbg_seed() for more information.
 */
#define IOTEX_CTR_DRBG_ENTROPY_NONCE_LEN 0
#else
/** The default length of the nonce read from the entropy source.
 *
 * This is half of the default entropy length because a single read from
 * the entropy source does not provide enough material to form a nonce.
 * See the documentation of iotex_ctr_drbg_seed() for more information.
 */
#define IOTEX_CTR_DRBG_ENTROPY_NONCE_LEN ( IOTEX_CTR_DRBG_ENTROPY_LEN + 1 ) / 2
#endif

/**
 * \brief          The CTR_DRBG context structure.
 */
typedef struct iotex_ctr_drbg_context
{
    unsigned char counter[16];  /*!< The counter (V). */
    int reseed_counter;         /*!< The reseed counter.
                                 * This is the number of requests that have
                                 * been made since the last (re)seeding,
                                 * minus one.
                                 * Before the initial seeding, this field
                                 * contains the amount of entropy in bytes
                                 * to use as a nonce for the initial seeding,
                                 * or -1 if no nonce length has been explicitly
                                 * set (see iotex_ctr_drbg_set_nonce_len()).
                                 */
    int prediction_resistance;  /*!< This determines whether prediction
                                     resistance is enabled, that is
                                     whether to systematically reseed before
                                     each random generation. */
    size_t entropy_len;         /*!< The amount of entropy grabbed on each
                                     seed or reseed operation, in bytes. */
    int reseed_interval;        /*!< The reseed interval.
                                 * This is the maximum number of requests
                                 * that can be made between reseedings. */

    iotex_aes_context aes_ctx;        /*!< The AES context. */

    /*
     * Callbacks (Entropy)
     */
    int (*f_entropy)(void *, unsigned char *, size_t);
                                /*!< The entropy callback function. */

    void *p_entropy;            /*!< The context for the entropy function. */

#if defined(IOTEX_THREADING_C)
    iotex_threading_mutex_t mutex;
#endif
}
iotex_ctr_drbg_context;

/**
 * \brief               This function initializes the CTR_DRBG context,
 *                      and prepares it for iotex_ctr_drbg_seed()
 *                      or iotex_ctr_drbg_free().
 *
 * \note                The reseed interval is
 *                      #IOTEX_CTR_DRBG_RESEED_INTERVAL by default.
 *                      You can override it by calling
 *                      iotex_ctr_drbg_set_reseed_interval().
 *
 * \param ctx           The CTR_DRBG context to initialize.
 */
void iotex_ctr_drbg_init( iotex_ctr_drbg_context *ctx );

/**
 * \brief               This function seeds and sets up the CTR_DRBG
 *                      entropy source for future reseeds.
 *
 * A typical choice for the \p f_entropy and \p p_entropy parameters is
 * to use the entropy module:
 * - \p f_entropy is iotex_entropy_func();
 * - \p p_entropy is an instance of ::iotex_entropy_context initialized
 *   with iotex_entropy_init() (which registers the platform's default
 *   entropy sources).
 *
 * The entropy length is #IOTEX_CTR_DRBG_ENTROPY_LEN by default.
 * You can override it by calling iotex_ctr_drbg_set_entropy_len().
 *
 * The entropy nonce length is:
 * - \c 0 if the entropy length is at least 3/2 times the entropy length,
 *   which guarantees that the security strength is the maximum permitted
 *   by the key size and entropy length according to NIST SP 800-90A §10.2.1;
 * - Half the entropy length otherwise.
 * You can override it by calling iotex_ctr_drbg_set_nonce_len().
 * With the default entropy length, the entropy nonce length is
 * #IOTEX_CTR_DRBG_ENTROPY_NONCE_LEN.
 *
 * You can provide a nonce and personalization string in addition to the
 * entropy source, to make this instantiation as unique as possible.
 * See SP 800-90A §8.6.7 for more details about nonces.
 *
 * The _seed_material_ value passed to the derivation function in
 * the CTR_DRBG Instantiate Process described in NIST SP 800-90A §10.2.1.3.2
 * is the concatenation of the following strings:
 * - A string obtained by calling \p f_entropy function for the entropy
 *   length.
 */
#if IOTEX_CTR_DRBG_ENTROPY_NONCE_LEN == 0
/**
 * - If iotex_ctr_drbg_set_nonce_len() has been called, a string
 *   obtained by calling \p f_entropy function for the specified length.
 */
#else
/**
 * - A string obtained by calling \p f_entropy function for the entropy nonce
 *   length. If the entropy nonce length is \c 0, this function does not
 *   make a second call to \p f_entropy.
 */
#endif
#if defined(IOTEX_THREADING_C)
/**
 * \note                When Mbed TLS is built with threading support,
 *                      after this function returns successfully,
 *                      it is safe to call iotex_ctr_drbg_random()
 *                      from multiple threads. Other operations, including
 *                      reseeding, are not thread-safe.
 */
#endif /* IOTEX_THREADING_C */
/**
 * - The \p custom string.
 *
 * \note                To achieve the nominal security strength permitted
 *                      by CTR_DRBG, the entropy length must be:
 *                      - at least 16 bytes for a 128-bit strength
 *                      (maximum achievable strength when using AES-128);
 *                      - at least 32 bytes for a 256-bit strength
 *                      (maximum achievable strength when using AES-256).
 *
 *                      In addition, if you do not pass a nonce in \p custom,
 *                      the sum of the entropy length
 *                      and the entropy nonce length must be:
 *                      - at least 24 bytes for a 128-bit strength
 *                      (maximum achievable strength when using AES-128);
 *                      - at least 48 bytes for a 256-bit strength
 *                      (maximum achievable strength when using AES-256).
 *
 * \param ctx           The CTR_DRBG context to seed.
 *                      It must have been initialized with
 *                      iotex_ctr_drbg_init().
 *                      After a successful call to iotex_ctr_drbg_seed(),
 *                      you may not call iotex_ctr_drbg_seed() again on
 *                      the same context unless you call
 *                      iotex_ctr_drbg_free() and iotex_ctr_drbg_init()
 *                      again first.
 *                      After a failed call to iotex_ctr_drbg_seed(),
 *                      you must call iotex_ctr_drbg_free().
 * \param f_entropy     The entropy callback, taking as arguments the
 *                      \p p_entropy context, the buffer to fill, and the
 *                      length of the buffer.
 *                      \p f_entropy is always called with a buffer size
 *                      less than or equal to the entropy length.
 * \param p_entropy     The entropy context to pass to \p f_entropy.
 * \param custom        The personalization string.
 *                      This can be \c NULL, in which case the personalization
 *                      string is empty regardless of the value of \p len.
 * \param len           The length of the personalization string.
 *                      This must be at most
 *                      #IOTEX_CTR_DRBG_MAX_SEED_INPUT
 *                      - #IOTEX_CTR_DRBG_ENTROPY_LEN.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED on failure.
 */
int iotex_ctr_drbg_seed( iotex_ctr_drbg_context *ctx,
                   int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy,
                   const unsigned char *custom,
                   size_t len );

/**
 * \brief               This function resets CTR_DRBG context to the state immediately
 *                      after initial call of iotex_ctr_drbg_init().
 *
 * \param ctx           The CTR_DRBG context to clear.
 */
void iotex_ctr_drbg_free( iotex_ctr_drbg_context *ctx );

/**
 * \brief               This function turns prediction resistance on or off.
 *                      The default value is off.
 *
 * \note                If enabled, entropy is gathered at the beginning of
 *                      every call to iotex_ctr_drbg_random_with_add()
 *                      or iotex_ctr_drbg_random().
 *                      Only use this if your entropy source has sufficient
 *                      throughput.
 *
 * \param ctx           The CTR_DRBG context.
 * \param resistance    #IOTEX_CTR_DRBG_PR_ON or #IOTEX_CTR_DRBG_PR_OFF.
 */
void iotex_ctr_drbg_set_prediction_resistance( iotex_ctr_drbg_context *ctx,
                                         int resistance );

/**
 * \brief               This function sets the amount of entropy grabbed on each
 *                      seed or reseed.
 *
 * The default value is #IOTEX_CTR_DRBG_ENTROPY_LEN.
 *
 * \note                The security strength of CTR_DRBG is bounded by the
 *                      entropy length. Thus:
 *                      - When using AES-256
 *                        (\c IOTEX_CTR_DRBG_USE_128_BIT_KEY is disabled,
 *                        which is the default),
 *                        \p len must be at least 32 (in bytes)
 *                        to achieve a 256-bit strength.
 *                      - When using AES-128
 *                        (\c IOTEX_CTR_DRBG_USE_128_BIT_KEY is enabled)
 *                        \p len must be at least 16 (in bytes)
 *                        to achieve a 128-bit strength.
 *
 * \param ctx           The CTR_DRBG context.
 * \param len           The amount of entropy to grab, in bytes.
 *                      This must be at most #IOTEX_CTR_DRBG_MAX_SEED_INPUT
 *                      and at most the maximum length accepted by the
 *                      entropy function that is set in the context.
 */
void iotex_ctr_drbg_set_entropy_len( iotex_ctr_drbg_context *ctx,
                               size_t len );

/**
 * \brief               This function sets the amount of entropy grabbed
 *                      as a nonce for the initial seeding.
 *
 * Call this function before calling iotex_ctr_drbg_seed() to read
 * a nonce from the entropy source during the initial seeding.
 *
 * \param ctx           The CTR_DRBG context.
 * \param len           The amount of entropy to grab for the nonce, in bytes.
 *                      This must be at most #IOTEX_CTR_DRBG_MAX_SEED_INPUT
 *                      and at most the maximum length accepted by the
 *                      entropy function that is set in the context.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CTR_DRBG_INPUT_TOO_BIG if \p len is
 *                      more than #IOTEX_CTR_DRBG_MAX_SEED_INPUT.
 * \return              #IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 *                      if the initial seeding has already taken place.
 */
int iotex_ctr_drbg_set_nonce_len( iotex_ctr_drbg_context *ctx,
                                    size_t len );

/**
 * \brief               This function sets the reseed interval.
 *
 * The reseed interval is the number of calls to iotex_ctr_drbg_random()
 * or iotex_ctr_drbg_random_with_add() after which the entropy function
 * is called again.
 *
 * The default value is #IOTEX_CTR_DRBG_RESEED_INTERVAL.
 *
 * \param ctx           The CTR_DRBG context.
 * \param interval      The reseed interval.
 */
void iotex_ctr_drbg_set_reseed_interval( iotex_ctr_drbg_context *ctx,
                                   int interval );

/**
 * \brief               This function reseeds the CTR_DRBG context, that is
 *                      extracts data from the entropy source.
 *
 * \note                This function is not thread-safe. It is not safe
 *                      to call this function if another thread might be
 *                      concurrently obtaining random numbers from the same
 *                      context or updating or reseeding the same context.
 *
 * \param ctx           The CTR_DRBG context.
 * \param additional    Additional data to add to the state. Can be \c NULL.
 * \param len           The length of the additional data.
 *                      This must be less than
 *                      #IOTEX_CTR_DRBG_MAX_SEED_INPUT - \c entropy_len
 *                      where \c entropy_len is the entropy length
 *                      configured for the context.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED on failure.
 */
int iotex_ctr_drbg_reseed( iotex_ctr_drbg_context *ctx,
                     const unsigned char *additional, size_t len );

/**
 * \brief              This function updates the state of the CTR_DRBG context.
 *
 * \note                This function is not thread-safe. It is not safe
 *                      to call this function if another thread might be
 *                      concurrently obtaining random numbers from the same
 *                      context or updating or reseeding the same context.
 *
 * \param ctx          The CTR_DRBG context.
 * \param additional   The data to update the state with. This must not be
 *                     \c NULL unless \p add_len is \c 0.
 * \param add_len      Length of \p additional in bytes. This must be at
 *                     most #IOTEX_CTR_DRBG_MAX_SEED_INPUT.
 *
 * \return             \c 0 on success.
 * \return             #IOTEX_ERR_CTR_DRBG_INPUT_TOO_BIG if
 *                     \p add_len is more than
 *                     #IOTEX_CTR_DRBG_MAX_SEED_INPUT.
 * \return             An error from the underlying AES cipher on failure.
 */
int iotex_ctr_drbg_update( iotex_ctr_drbg_context *ctx,
                             const unsigned char *additional,
                             size_t add_len );

/**
 * \brief   This function updates a CTR_DRBG instance with additional
 *          data and uses it to generate random data.
 *
 * This function automatically reseeds if the reseed counter is exceeded
 * or prediction resistance is enabled.
 *
 * \note                This function is not thread-safe. It is not safe
 *                      to call this function if another thread might be
 *                      concurrently obtaining random numbers from the same
 *                      context or updating or reseeding the same context.
 *
 * \param p_rng         The CTR_DRBG context. This must be a pointer to a
 *                      #iotex_ctr_drbg_context structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer in bytes.
 * \param additional    Additional data to update. Can be \c NULL, in which
 *                      case the additional data is empty regardless of
 *                      the value of \p add_len.
 * \param add_len       The length of the additional data
 *                      if \p additional is not \c NULL.
 *                      This must be less than #IOTEX_CTR_DRBG_MAX_INPUT
 *                      and less than
 *                      #IOTEX_CTR_DRBG_MAX_SEED_INPUT - \c entropy_len
 *                      where \c entropy_len is the entropy length
 *                      configured for the context.
 *
 * \return    \c 0 on success.
 * \return    #IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *            #IOTEX_ERR_CTR_DRBG_REQUEST_TOO_BIG on failure.
 */
int iotex_ctr_drbg_random_with_add( void *p_rng,
                              unsigned char *output, size_t output_len,
                              const unsigned char *additional, size_t add_len );

/**
 * \brief   This function uses CTR_DRBG to generate random data.
 *
 * This function automatically reseeds if the reseed counter is exceeded
 * or prediction resistance is enabled.
 */
#if defined(IOTEX_THREADING_C)
/**
 * \note                When Mbed TLS is built with threading support,
 *                      it is safe to call iotex_ctr_drbg_random()
 *                      from multiple threads. Other operations, including
 *                      reseeding, are not thread-safe.
 */
#endif /* IOTEX_THREADING_C */
/**
 * \param p_rng         The CTR_DRBG context. This must be a pointer to a
 *                      #iotex_ctr_drbg_context structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer in bytes.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *                      #IOTEX_ERR_CTR_DRBG_REQUEST_TOO_BIG on failure.
 */
int iotex_ctr_drbg_random( void *p_rng,
                     unsigned char *output, size_t output_len );

#if defined(IOTEX_FS_IO)
/**
 * \brief               This function writes a seed file.
 *
 * \param ctx           The CTR_DRBG context.
 * \param path          The name of the file.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CTR_DRBG_FILE_IO_ERROR on file error.
 * \return              #IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED on reseed
 *                      failure.
 */
int iotex_ctr_drbg_write_seed_file( iotex_ctr_drbg_context *ctx, const char *path );

/**
 * \brief               This function reads and updates a seed file. The seed
 *                      is added to this instance.
 *
 * \param ctx           The CTR_DRBG context.
 * \param path          The name of the file.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_CTR_DRBG_FILE_IO_ERROR on file error.
 * \return              #IOTEX_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED on
 *                      reseed failure.
 * \return              #IOTEX_ERR_CTR_DRBG_INPUT_TOO_BIG if the existing
 *                      seed file is too large.
 */
int iotex_ctr_drbg_update_seed_file( iotex_ctr_drbg_context *ctx, const char *path );
#endif /* IOTEX_FS_IO */

#if defined(IOTEX_SELF_TEST)

/**
 * \brief               The CTR_DRBG checkup routine.
 *
 * \return              \c 0 on success.
 * \return              \c 1 on failure.
 */
int iotex_ctr_drbg_self_test( int verbose );

#endif /* IOTEX_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* ctr_drbg.h */
