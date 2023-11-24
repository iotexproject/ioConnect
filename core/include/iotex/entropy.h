#ifndef IOTEXCRYPT_ENTROPY_H
#define IOTEXCRYPT_ENTROPY_H

#include "include/iotex/build_info.h"

#include <stddef.h>

#if defined(IOTEX_SHA512_C) && !defined(IOTEX_ENTROPY_FORCE_SHA256)
#include "include/iotex/sha512.h"
#define IOTEX_ENTROPY_SHA512_ACCUMULATOR
#else
#if defined(IOTEX_SHA256_C)
#define IOTEX_ENTROPY_SHA256_ACCUMULATOR
#include "include/iotex/sha256.h"
#endif
#endif

/** Critical entropy source failure. */
#define IOTEX_ERR_ENTROPY_SOURCE_FAILED                 -0x003C
/** No more sources can be added. */
#define IOTEX_ERR_ENTROPY_MAX_SOURCES                   -0x003E
/** No sources have been added to poll. */
#define IOTEX_ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040
/** No strong sources have been added to poll. */
#define IOTEX_ERR_ENTROPY_NO_STRONG_SOURCE              -0x003D
/** Read/write error in file. */
#define IOTEX_ERR_ENTROPY_FILE_IO_ERROR                 -0x003F

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in iotex_config.h or define them on the compiler command line.
 * \{
 */

#if !defined(IOTEX_ENTROPY_MAX_SOURCES)
#define IOTEX_ENTROPY_MAX_SOURCES       5      /**< Maximum number of sources supported */
#endif

#if !defined(IOTEX_ENTROPY_MAX_GATHER)
#define IOTEX_ENTROPY_MAX_GATHER      128     /**< Maximum amount requested from entropy sources */
#endif

/** \} name SECTION: Module settings */

#if defined(IOTEX_ENTROPY_SHA512_ACCUMULATOR)
#define IOTEX_ENTROPY_BLOCK_SIZE      64      /**< Block size of entropy accumulator (SHA-512) */
#else
#define IOTEX_ENTROPY_BLOCK_SIZE      32      /**< Block size of entropy accumulator (SHA-256) */
#endif

#define IOTEX_ENTROPY_MAX_SEED_SIZE   1024    /**< Maximum size of seed we read from seed file */
#define IOTEX_ENTROPY_SOURCE_MANUAL   IOTEX_ENTROPY_MAX_SOURCES

#define IOTEX_ENTROPY_SOURCE_STRONG   1       /**< Entropy source is strong   */
#define IOTEX_ENTROPY_SOURCE_WEAK     0       /**< Entropy source is weak     */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Entropy poll callback pointer
 *
 * \param data      Callback-specific data pointer
 * \param output    Data to fill
 * \param len       Maximum size to provide
 * \param olen      The actual amount of bytes put into the buffer (Can be 0)
 *
 * \return          0 if no critical failures occurred,
 *                  IOTEX_ERR_ENTROPY_SOURCE_FAILED otherwise
 */
typedef int (*iotex_entropy_f_source_ptr)(void *data, unsigned char *output, size_t len,
                            size_t *olen);

/**
 * \brief           Entropy source state
 */
typedef struct iotex_entropy_source_state
{
    iotex_entropy_f_source_ptr    f_source;   /**< The entropy source callback */
    void *          p_source;      /**< The callback data pointer */
    size_t          size;          /**< Amount received in bytes */
    size_t          threshold;     /**< Minimum bytes required before release */
    int             strong;        /**< Is the source strong? */
}
iotex_entropy_source_state;

/**
 * \brief           Entropy context structure
 */
typedef struct iotex_entropy_context
{
    int accumulator_started; /* 0 after init.
                              * 1 after the first update.
                              * -1 after free. */
#if defined(IOTEX_ENTROPY_SHA512_ACCUMULATOR)
    iotex_sha512_context  accumulator;
#elif defined(IOTEX_ENTROPY_SHA256_ACCUMULATOR)
    iotex_sha256_context  accumulator;
#endif
    int             source_count; /* Number of entries used in source. */
    iotex_entropy_source_state    source[IOTEX_ENTROPY_MAX_SOURCES];
#if defined(IOTEX_THREADING_C)
    iotex_threading_mutex_t mutex;
#endif
#if defined(IOTEX_ENTROPY_NV_SEED)
    int initial_entropy_run;
#endif
}
iotex_entropy_context;

#if !defined(IOTEX_NO_PLATFORM_ENTROPY)
/**
 * \brief           Platform-specific entropy poll callback
 */
int iotex_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );
#endif

/**
 * \brief           Initialize the context
 *
 * \param ctx       Entropy context to initialize
 */
void iotex_entropy_init( iotex_entropy_context *ctx );

/**
 * \brief           Free the data in the context
 *
 * \param ctx       Entropy context to free
 */
void iotex_entropy_free( iotex_entropy_context *ctx );

/**
 * \brief           Adds an entropy source to poll
 *                  (Thread-safe if IOTEX_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *                  ( with iotex_entropy_func() ) (in bytes)
 * \param strong    IOTEX_ENTROPY_SOURCE_STRONG or
 *                  IOTEX_ENTROPY_SOURCE_WEAK.
 *                  At least one strong source needs to be added.
 *                  Weaker sources (such as the cycle counter) can be used as
 *                  a complement.
 *
 * \return          0 if successful or IOTEX_ERR_ENTROPY_MAX_SOURCES
 */
int iotex_entropy_add_source( iotex_entropy_context *ctx,
                        iotex_entropy_f_source_ptr f_source, void *p_source,
                        size_t threshold, int strong );

/**
 * \brief           Trigger an extra gather poll for the accumulator
 *                  (Thread-safe if IOTEX_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful, or IOTEX_ERR_ENTROPY_SOURCE_FAILED
 */
int iotex_entropy_gather( iotex_entropy_context *ctx );

/**
 * \brief           Retrieve entropy from the accumulator
 *                  (Maximum length: IOTEX_ENTROPY_BLOCK_SIZE)
 *                  (Thread-safe if IOTEX_THREADING_C is enabled)
 *
 * \param data      Entropy context
 * \param output    Buffer to fill
 * \param len       Number of bytes desired, must be at most IOTEX_ENTROPY_BLOCK_SIZE
 *
 * \return          0 if successful, or IOTEX_ERR_ENTROPY_SOURCE_FAILED
 */
int iotex_entropy_func( void *data, unsigned char *output, size_t len );

/**
 * \brief           Add data to the accumulator manually
 *                  (Thread-safe if IOTEX_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param data      Data to add
 * \param len       Length of data
 *
 * \return          0 if successful
 */
int iotex_entropy_update_manual( iotex_entropy_context *ctx,
                           const unsigned char *data, size_t len );

#if defined(IOTEX_ENTROPY_NV_SEED)
/**
 * \brief           Trigger an update of the seed file in NV by using the
 *                  current entropy pool.
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful
 */
int iotex_entropy_update_nv_seed( iotex_entropy_context *ctx );
#endif /* IOTEX_ENTROPY_NV_SEED */

#if defined(IOTEX_FS_IO)
/**
 * \brief               Write a seed file
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      IOTEX_ERR_ENTROPY_FILE_IO_ERROR on file error, or
 *                      IOTEX_ERR_ENTROPY_SOURCE_FAILED
 */
int iotex_entropy_write_seed_file( iotex_entropy_context *ctx, const char *path );

/**
 * \brief               Read and update a seed file. Seed is added to this
 *                      instance. No more than IOTEX_ENTROPY_MAX_SEED_SIZE bytes are
 *                      read from the seed file. The rest is ignored.
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      IOTEX_ERR_ENTROPY_FILE_IO_ERROR on file error,
 *                      IOTEX_ERR_ENTROPY_SOURCE_FAILED
 */
int iotex_entropy_update_seed_file( iotex_entropy_context *ctx, const char *path );
#endif /* IOTEX_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* entropy.h */
