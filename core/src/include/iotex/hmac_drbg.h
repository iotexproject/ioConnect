#ifndef IOTEX_HMAC_DRBG_H
#define IOTEX_HMAC_DRBG_H

#include "include/iotex/build_info.h"

#include "include/iotex/md.h"

/*
 * Error codes
 */
/** Too many random requested in single call. */
#define IOTEX_ERR_HMAC_DRBG_REQUEST_TOO_BIG              -0x0003
/** Input too large (Entropy + additional). */
#define IOTEX_ERR_HMAC_DRBG_INPUT_TOO_BIG                -0x0005
/** Read/write error in file. */
#define IOTEX_ERR_HMAC_DRBG_FILE_IO_ERROR                -0x0007
/** The entropy source failed. */
#define IOTEX_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED        -0x0009

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in iotex_config.h or define them on the compiler command line.
 * \{
 */

#if !defined(IOTEX_HMAC_DRBG_RESEED_INTERVAL)
#define IOTEX_HMAC_DRBG_RESEED_INTERVAL   10000   /**< Interval before reseed is performed by default */
#endif

#if !defined(IOTEX_HMAC_DRBG_MAX_INPUT)
#define IOTEX_HMAC_DRBG_MAX_INPUT         256     /**< Maximum number of additional input bytes */
#endif

#if !defined(IOTEX_HMAC_DRBG_MAX_REQUEST)
#define IOTEX_HMAC_DRBG_MAX_REQUEST       1024    /**< Maximum number of requested bytes per call */
#endif

#if !defined(IOTEX_HMAC_DRBG_MAX_SEED_INPUT)
#define IOTEX_HMAC_DRBG_MAX_SEED_INPUT    384     /**< Maximum size of (re)seed buffer */
#endif

/** \} name SECTION: Module settings */

#define IOTEX_HMAC_DRBG_PR_OFF   0   /**< No prediction resistance       */
#define IOTEX_HMAC_DRBG_PR_ON    1   /**< Prediction resistance enabled  */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC_DRBG context.
 */
typedef struct iotex_hmac_drbg_context
{
    /* Working state: the key K is not stored explicitly,
     * but is implied by the HMAC context */
    iotex_md_context_t md_ctx;                      /*!< HMAC context (inc. K)  */
    unsigned char V[IOTEX_MD_MAX_SIZE];             /*!< V in the spec          */
    int reseed_counter;                             /*!< reseed counter         */

    /* Administrative state */
    size_t entropy_len;         /*!< entropy bytes grabbed on each (re)seed */
    int prediction_resistance;  /*!< enable prediction resistance (Automatic
                                     reseed before every random generation) */
    int reseed_interval;        /*!< reseed interval   */

    /* Callbacks */
    int (*(f_entropy))(void *, unsigned char *, size_t); /*!< entropy function */
    void *(p_entropy);            /*!< context for the entropy function        */

} iotex_hmac_drbg_context;

/**
 * \brief               HMAC_DRBG context initialization.
 *
 * This function makes the context ready for iotex_hmac_drbg_seed(),
 * iotex_hmac_drbg_seed_buf() or iotex_hmac_drbg_free().
 *
 * \note                The reseed interval is #IOTEX_HMAC_DRBG_RESEED_INTERVAL
 *                      by default. Override this value by calling
 *                      iotex_hmac_drbg_set_reseed_interval().
 *
 * \param ctx           HMAC_DRBG context to be initialized.
 */
void iotex_hmac_drbg_init( iotex_hmac_drbg_context *ctx );

/**
 * \brief               HMAC_DRBG initial seeding.
 *
 * Set the initial seed and set up the entropy source for future reseeds.
 *
 * A typical choice for the \p f_entropy and \p p_entropy parameters is
 * to use the entropy module:
 * - \p f_entropy is iotex_entropy_func();
 * - \p p_entropy is an instance of ::iotex_entropy_context initialized
 *   with iotex_entropy_init() (which registers the platform's default
 *   entropy sources).
 *
 * You can provide a personalization string in addition to the
 * entropy source, to make this instantiation as unique as possible.
 *
 * \note                By default, the security strength as defined by NIST is:
 *                      - 128 bits if \p md_info is SHA-1;
 *                      - 192 bits if \p md_info is SHA-224;
 *                      - 256 bits if \p md_info is SHA-256, SHA-384 or SHA-512.
 *                      Note that SHA-256 is just as efficient as SHA-224.
 *                      The security strength can be reduced if a smaller
 *                      entropy length is set with
 *                      iotex_hmac_drbg_set_entropy_len().
 *
 * \note                The default entropy length is the security strength
 *                      (converted from bits to bytes). You can override
 *                      it by calling iotex_hmac_drbg_set_entropy_len().
 *
 * \note                During the initial seeding, this function calls
 *                      the entropy source to obtain a nonce
 *                      whose length is half the entropy length.
 */
#if defined(IOTEX_THREADING_C)
/**
 * \note                When Mbed TLS is built with threading support,
 *                      after this function returns successfully,
 *                      it is safe to call iotex_hmac_drbg_random()
 *                      from multiple threads. Other operations, including
 *                      reseeding, are not thread-safe.
 */
#endif /* IOTEX_THREADING_C */
/**
 * \param ctx           HMAC_DRBG context to be seeded.
 * \param md_info       MD algorithm to use for HMAC_DRBG.
 * \param f_entropy     The entropy callback, taking as arguments the
 *                      \p p_entropy context, the buffer to fill, and the
 *                      length of the buffer.
 *                      \p f_entropy is always called with a length that is
 *                      less than or equal to the entropy length.
 * \param p_entropy     The entropy context to pass to \p f_entropy.
 * \param custom        The personalization string.
 *                      This can be \c NULL, in which case the personalization
 *                      string is empty regardless of the value of \p len.
 * \param len           The length of the personalization string.
 *                      This must be at most #IOTEX_HMAC_DRBG_MAX_INPUT
 *                      and also at most
 *                      #IOTEX_HMAC_DRBG_MAX_SEED_INPUT - \p entropy_len * 3 / 2
 *                      where \p entropy_len is the entropy length
 *                      described above.
 *
 * \return              \c 0 if successful.
 * \return              #IOTEX_ERR_MD_BAD_INPUT_DATA if \p md_info is
 *                      invalid.
 * \return              #IOTEX_ERR_MD_ALLOC_FAILED if there was not enough
 *                      memory to allocate context data.
 * \return              #IOTEX_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if the call to \p f_entropy failed.
 */
int iotex_hmac_drbg_seed( iotex_hmac_drbg_context *ctx,
                    const iotex_md_info_t * md_info,
                    int (*f_entropy)(void *, unsigned char *, size_t),
                    void *p_entropy,
                    const unsigned char *custom,
                    size_t len );

/**
 * \brief               Initialisation of simplified HMAC_DRBG (never reseeds).
 *
 * This function is meant for use in algorithms that need a pseudorandom
 * input such as deterministic ECDSA.
 */
#if defined(IOTEX_THREADING_C)
/**
 * \note                When Mbed TLS is built with threading support,
 *                      after this function returns successfully,
 *                      it is safe to call iotex_hmac_drbg_random()
 *                      from multiple threads. Other operations, including
 *                      reseeding, are not thread-safe.
 */
#endif /* IOTEX_THREADING_C */
/**
 * \param ctx           HMAC_DRBG context to be initialised.
 * \param md_info       MD algorithm to use for HMAC_DRBG.
 * \param data          Concatenation of the initial entropy string and
 *                      the additional data.
 * \param data_len      Length of \p data in bytes.
 *
 * \return              \c 0 if successful. or
 * \return              #IOTEX_ERR_MD_BAD_INPUT_DATA if \p md_info is
 *                      invalid.
 * \return              #IOTEX_ERR_MD_ALLOC_FAILED if there was not enough
 *                      memory to allocate context data.
 */
// int iotex_hmac_drbg_seed_buf( iotex_hmac_drbg_context *ctx,
//                         const iotex_md_info_t * md_info,
//                         const unsigned char *data, size_t data_len );

/**
 * \brief               This function turns prediction resistance on or off.
 *                      The default value is off.
 *
 * \note                If enabled, entropy is gathered at the beginning of
 *                      every call to iotex_hmac_drbg_random_with_add()
 *                      or iotex_hmac_drbg_random().
 *                      Only use this if your entropy source has sufficient
 *                      throughput.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param resistance    #IOTEX_HMAC_DRBG_PR_ON or #IOTEX_HMAC_DRBG_PR_OFF.
 */
void iotex_hmac_drbg_set_prediction_resistance( iotex_hmac_drbg_context *ctx,
                                          int resistance );

/**
 * \brief               This function sets the amount of entropy grabbed on each
 *                      seed or reseed.
 *
 * See the documentation of iotex_hmac_drbg_seed() for the default value.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param len           The amount of entropy to grab, in bytes.
 */
void iotex_hmac_drbg_set_entropy_len( iotex_hmac_drbg_context *ctx,
                                size_t len );

/**
 * \brief               Set the reseed interval.
 *
 * The reseed interval is the number of calls to iotex_hmac_drbg_random()
 * or iotex_hmac_drbg_random_with_add() after which the entropy function
 * is called again.
 *
 * The default value is #IOTEX_HMAC_DRBG_RESEED_INTERVAL.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param interval      The reseed interval.
 */
void iotex_hmac_drbg_set_reseed_interval( iotex_hmac_drbg_context *ctx,
                                    int interval );

/**
 * \brief               This function updates the state of the HMAC_DRBG context.
 *
 * \note                This function is not thread-safe. It is not safe
 *                      to call this function if another thread might be
 *                      concurrently obtaining random numbers from the same
 *                      context or updating or reseeding the same context.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param additional    The data to update the state with.
 *                      If this is \c NULL, there is no additional data.
 * \param add_len       Length of \p additional in bytes.
 *                      Unused if \p additional is \c NULL.
 *
 * \return              \c 0 on success, or an error from the underlying
 *                      hash calculation.
 */
int iotex_hmac_drbg_update( iotex_hmac_drbg_context *ctx,
                              const unsigned char *additional, size_t add_len );

/**
 * \brief               This function reseeds the HMAC_DRBG context, that is
 *                      extracts data from the entropy source.
 *
 * \note                This function is not thread-safe. It is not safe
 *                      to call this function if another thread might be
 *                      concurrently obtaining random numbers from the same
 *                      context or updating or reseeding the same context.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param additional    Additional data to add to the state.
 *                      If this is \c NULL, there is no additional data
 *                      and \p len should be \c 0.
 * \param len           The length of the additional data.
 *                      This must be at most #IOTEX_HMAC_DRBG_MAX_INPUT
 *                      and also at most
 *                      #IOTEX_HMAC_DRBG_MAX_SEED_INPUT - \p entropy_len
 *                      where \p entropy_len is the entropy length
 *                      (see iotex_hmac_drbg_set_entropy_len()).
 *
 * \return              \c 0 if successful.
 * \return              #IOTEX_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if a call to the entropy function failed.
 */
int iotex_hmac_drbg_reseed( iotex_hmac_drbg_context *ctx,
                      const unsigned char *additional, size_t len );

/**
 * \brief   This function updates an HMAC_DRBG instance with additional
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
 * \param p_rng         The HMAC_DRBG context. This must be a pointer to a
 *                      #iotex_hmac_drbg_context structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer in bytes.
 *                      This must be at most #IOTEX_HMAC_DRBG_MAX_REQUEST.
 * \param additional    Additional data to update with.
 *                      If this is \c NULL, there is no additional data
 *                      and \p add_len should be \c 0.
 * \param add_len       The length of the additional data.
 *                      This must be at most #IOTEX_HMAC_DRBG_MAX_INPUT.
 *
 * \return              \c 0 if successful.
 * \return              #IOTEX_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if a call to the entropy source failed.
 * \return              #IOTEX_ERR_HMAC_DRBG_REQUEST_TOO_BIG if
 *                      \p output_len > #IOTEX_HMAC_DRBG_MAX_REQUEST.
 * \return              #IOTEX_ERR_HMAC_DRBG_INPUT_TOO_BIG if
 *                      \p add_len > #IOTEX_HMAC_DRBG_MAX_INPUT.
 */
int iotex_hmac_drbg_random_with_add( void *p_rng,
                               unsigned char *output, size_t output_len,
                               const unsigned char *additional,
                               size_t add_len );

/**
 * \brief   This function uses HMAC_DRBG to generate random data.
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
 * \param p_rng         The HMAC_DRBG context. This must be a pointer to a
 *                      #iotex_hmac_drbg_context structure.
 * \param output        The buffer to fill.
 * \param out_len       The length of the buffer in bytes.
 *                      This must be at most #IOTEX_HMAC_DRBG_MAX_REQUEST.
 *
 * \return              \c 0 if successful.
 * \return              #IOTEX_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if a call to the entropy source failed.
 * \return              #IOTEX_ERR_HMAC_DRBG_REQUEST_TOO_BIG if
 *                      \p out_len > #IOTEX_HMAC_DRBG_MAX_REQUEST.
 */
int iotex_hmac_drbg_random( void *p_rng, unsigned char *output, size_t out_len );

/**
 * \brief               This function resets HMAC_DRBG context to the state immediately
 *                      after initial call of iotex_hmac_drbg_init().
 *
 * \param ctx           The HMAC_DRBG context to free.
 */
void iotex_hmac_drbg_free( iotex_hmac_drbg_context *ctx );

#if defined(IOTEX_FS_IO)
/**
 * \brief               This function writes a seed file.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param path          The name of the file.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_HMAC_DRBG_FILE_IO_ERROR on file error.
 * \return              #IOTEX_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED on reseed
 *                      failure.
 */
int iotex_hmac_drbg_write_seed_file( iotex_hmac_drbg_context *ctx, const char *path );

/**
 * \brief               This function reads and updates a seed file. The seed
 *                      is added to this instance.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param path          The name of the file.
 *
 * \return              \c 0 on success.
 * \return              #IOTEX_ERR_HMAC_DRBG_FILE_IO_ERROR on file error.
 * \return              #IOTEX_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED on
 *                      reseed failure.
 * \return              #IOTEX_ERR_HMAC_DRBG_INPUT_TOO_BIG if the existing
 *                      seed file is too large.
 */
int iotex_hmac_drbg_update_seed_file( iotex_hmac_drbg_context *ctx, const char *path );
#endif /* IOTEX_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* hmac_drbg.h */
