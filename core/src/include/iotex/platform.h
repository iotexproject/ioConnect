#ifndef IOTEX_PLATFORM_H
#define IOTEX_PLATFORM_H

#include "include/iotex/build_info.h"

#if defined(IOTEX_HAVE_TIME)
#include "include/iotex/platform_time.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in iotex_config.h or define them on the compiler command line.
 * \{
 */

/* The older Microsoft Windows common runtime provides non-conforming
 * implementations of some standard library functions, including snprintf
 * and vsnprintf. This affects MSVC and MinGW builds.
 */
#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER <= 1900)
#define IOTEX_PLATFORM_HAS_NON_CONFORMING_SNPRINTF
#define IOTEX_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF
#endif

#if  defined ( __GNUC__ ) || defined(__MINGW32__)
#ifndef __weak
#define __weak  __attribute__((weak))
#endif /* __weak */
#ifndef __packed
#define __packed  __attribute__((__packed__))
#endif /* __packed */
#endif /* __GNUC__ */

#if !defined(IOTEX_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#if defined(IOTEX_HAVE_TIME)
#include <time.h>
#endif
#if !defined(IOTEX_PLATFORM_STD_SNPRINTF)
#if defined(IOTEX_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)
#define IOTEX_PLATFORM_STD_SNPRINTF   iotex_platform_win32_snprintf /**< The default \c snprintf function to use.  */
#else
#define IOTEX_PLATFORM_STD_SNPRINTF   snprintf /**< The default \c snprintf function to use.  */
#endif
#endif
#if !defined(IOTEX_PLATFORM_STD_VSNPRINTF)
#if defined(IOTEX_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#define IOTEX_PLATFORM_STD_VSNPRINTF   iotex_platform_win32_vsnprintf /**< The default \c vsnprintf function to use.  */
#else
#define IOTEX_PLATFORM_STD_VSNPRINTF   vsnprintf /**< The default \c vsnprintf function to use.  */
#endif
#endif
#if !defined(IOTEX_PLATFORM_STD_PRINTF)
#define IOTEX_PLATFORM_STD_PRINTF   printf /**< The default \c printf function to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_FPRINTF)
#define IOTEX_PLATFORM_STD_FPRINTF fprintf /**< The default \c fprintf function to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_CALLOC)
#define IOTEX_PLATFORM_STD_CALLOC   calloc /**< The default \c calloc function to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_FREE)
#define IOTEX_PLATFORM_STD_FREE       free /**< The default \c free function to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_SETBUF)
#define IOTEX_PLATFORM_STD_SETBUF   setbuf /**< The default \c setbuf function to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_EXIT)
#define IOTEX_PLATFORM_STD_EXIT      exit /**< The default \c exit function to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_TIME)
#define IOTEX_PLATFORM_STD_TIME       time    /**< The default \c time function to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_EXIT_SUCCESS)
#define IOTEX_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS /**< The default exit value to use. */
#endif
#if !defined(IOTEX_PLATFORM_STD_EXIT_FAILURE)
#define IOTEX_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE /**< The default exit value to use. */
#endif
#if defined(IOTEX_FS_IO)
#if !defined(IOTEX_PLATFORM_STD_NV_SEED_READ)
#define IOTEX_PLATFORM_STD_NV_SEED_READ   iotex_platform_std_nv_seed_read
#endif
#if !defined(IOTEX_PLATFORM_STD_NV_SEED_WRITE)
#define IOTEX_PLATFORM_STD_NV_SEED_WRITE  iotex_platform_std_nv_seed_write
#endif
#if !defined(IOTEX_PLATFORM_STD_NV_SEED_FILE)
#define IOTEX_PLATFORM_STD_NV_SEED_FILE   "seedfile"
#endif
#endif /* IOTEX_FS_IO */
#else /* IOTEX_PLATFORM_NO_STD_FUNCTIONS */
#if defined(IOTEX_PLATFORM_STD_MEM_HDR)
#include IOTEX_PLATFORM_STD_MEM_HDR
#endif
#endif /* IOTEX_PLATFORM_NO_STD_FUNCTIONS */


/** \} name SECTION: Module settings */

/*
 * The function pointers for calloc and free.
 */
#if defined(IOTEX_PLATFORM_MEMORY)
#if defined(IOTEX_PLATFORM_FREE_MACRO) && \
    defined(IOTEX_PLATFORM_CALLOC_MACRO)
#define iotex_free       IOTEX_PLATFORM_FREE_MACRO
#define iotex_calloc     IOTEX_PLATFORM_CALLOC_MACRO
#else
/* For size_t */
#include <stddef.h>
extern void *iotex_calloc( size_t n, size_t size );
extern void iotex_free( void *ptr );

/**
 * \brief               This function dynamically sets the memory-management
 *                      functions used by the library, during runtime.
 *
 * \param calloc_func   The \c calloc function implementation.
 * \param free_func     The \c free function implementation.
 *
 * \return              \c 0.
 */
int iotex_platform_set_calloc_free( void * (*calloc_func)( size_t, size_t ),
                              void (*free_func)( void * ) );
#endif /* IOTEX_PLATFORM_FREE_MACRO && IOTEX_PLATFORM_CALLOC_MACRO */
#else /* !IOTEX_PLATFORM_MEMORY */
#define iotex_free       free
#define iotex_calloc     calloc
#endif /* IOTEX_PLATFORM_MEMORY && !IOTEX_PLATFORM_{FREE,CALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */
#if defined(IOTEX_PLATFORM_FPRINTF_ALT)
/* We need FILE * */
#include <stdio.h>
extern int (*iotex_fprintf)( FILE *stream, const char *format, ... );

/**
 * \brief                This function dynamically configures the fprintf
 *                       function that is called when the
 *                       iotex_fprintf() function is invoked by the library.
 *
 * \param fprintf_func   The \c fprintf function implementation.
 *
 * \return               \c 0.
 */
int iotex_platform_set_fprintf( int (*fprintf_func)( FILE *stream, const char *,
                                               ... ) );
#else
#if defined(IOTEX_PLATFORM_FPRINTF_MACRO)
#define iotex_fprintf    IOTEX_PLATFORM_FPRINTF_MACRO
#else
#define iotex_fprintf    fprintf
#endif /* IOTEX_PLATFORM_FPRINTF_MACRO */
#endif /* IOTEX_PLATFORM_FPRINTF_ALT */

/*
 * The function pointers for printf
 */
#if defined(IOTEX_PLATFORM_PRINTF_ALT)
extern int (*iotex_printf)( const char *format, ... );

/**
 * \brief               This function dynamically configures the snprintf
 *                      function that is called when the iotex_snprintf()
 *                      function is invoked by the library.
 *
 * \param printf_func   The \c printf function implementation.
 *
 * \return              \c 0 on success.
 */
int iotex_platform_set_printf( int (*printf_func)( const char *, ... ) );
#else /* !IOTEX_PLATFORM_PRINTF_ALT */
#if defined(IOTEX_PLATFORM_PRINTF_MACRO)
#define iotex_printf     IOTEX_PLATFORM_PRINTF_MACRO
#else
#define iotex_printf     printf
#endif /* IOTEX_PLATFORM_PRINTF_MACRO */
#endif /* IOTEX_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for snprintf
 *
 * The snprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */
#if defined(IOTEX_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)
/* For Windows (inc. MSYS2), we provide our own fixed implementation */
int iotex_platform_win32_snprintf( char *s, size_t n, const char *fmt, ... );
#endif

#if defined(IOTEX_PLATFORM_SNPRINTF_ALT)
extern int (*iotex_snprintf)( char * s, size_t n, const char * format, ... );

/**
 * \brief                 This function allows configuring a custom
 *                        \c snprintf function pointer.
 *
 * \param snprintf_func   The \c snprintf function implementation.
 *
 * \return                \c 0 on success.
 */
int iotex_platform_set_snprintf( int (*snprintf_func)( char * s, size_t n,
                                                 const char * format, ... ) );
#else /* IOTEX_PLATFORM_SNPRINTF_ALT */
#if defined(IOTEX_PLATFORM_SNPRINTF_MACRO)
#define iotex_snprintf   IOTEX_PLATFORM_SNPRINTF_MACRO
#else
#define iotex_snprintf   snprintf
#endif /* IOTEX_PLATFORM_SNPRINTF_MACRO */
#endif /* IOTEX_PLATFORM_SNPRINTF_ALT */

/*
 * The function pointers for vsnprintf
 *
 * The vsnprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */
#if defined(IOTEX_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#include <stdarg.h>
/* For Older Windows (inc. MSYS2), we provide our own fixed implementation */
int iotex_platform_win32_vsnprintf( char *s, size_t n, const char *fmt, va_list arg );
#endif

#if defined(IOTEX_PLATFORM_VSNPRINTF_ALT)
#include <stdarg.h>
extern int (*iotex_vsnprintf)( char * s, size_t n, const char * format, va_list arg );

/**
 * \brief   Set your own snprintf function pointer
 *
 * \param   vsnprintf_func   The \c vsnprintf function implementation
 *
 * \return  \c 0
 */
int iotex_platform_set_vsnprintf( int (*vsnprintf_func)( char * s, size_t n,
                                                 const char * format, va_list arg ) );
#else /* IOTEX_PLATFORM_VSNPRINTF_ALT */
#if defined(IOTEX_PLATFORM_VSNPRINTF_MACRO)
#define iotex_vsnprintf   IOTEX_PLATFORM_VSNPRINTF_MACRO
#else
#define iotex_vsnprintf   vsnprintf
#endif /* IOTEX_PLATFORM_VSNPRINTF_MACRO */
#endif /* IOTEX_PLATFORM_VSNPRINTF_ALT */

/*
 * The function pointers for setbuf
 */
#if defined(IOTEX_PLATFORM_SETBUF_ALT)
#include <stdio.h>
/**
 * \brief                  Function pointer to call for `setbuf()` functionality
 *                         (changing the internal buffering on stdio calls).
 *
 * \note                   The library calls this function to disable
 *                         buffering when reading or writing sensitive data,
 *                         to avoid having extra copies of sensitive data
 *                         remaining in stdio buffers after the file is
 *                         closed. If this is not a concern, for example if
 *                         your platform's stdio doesn't have any buffering,
 *                         you can set iotex_setbuf to a function that
 *                         does nothing.
 *
 *                         The library always calls this function with
 *                         `buf` equal to `NULL`.
 */
extern void (*iotex_setbuf)( FILE *stream, char *buf );

/**
 * \brief                  Dynamically configure the function that is called
 *                         when the iotex_setbuf() function is called by the
 *                         library.
 *
 * \param   setbuf_func   The \c setbuf function implementation
 *
 * \return                 \c 0
 */
int iotex_platform_set_setbuf( void (*setbuf_func)(
                                     FILE *stream, char *buf ) );
#elif defined(IOTEX_PLATFORM_SETBUF_MACRO)
/**
 * \brief                  Macro defining the function for the library to
 *                         call for `setbuf` functionality (changing the
 *                         internal buffering on stdio calls).
 *
 * \note                   See extra comments on the iotex_setbuf() function
 *                         pointer above.
 *
 * \return                 \c 0 on success, negative on error.
 */
#define iotex_setbuf    IOTEX_PLATFORM_SETBUF_MACRO
#else
#define iotex_setbuf    setbuf
#endif /* IOTEX_PLATFORM_SETBUF_ALT / IOTEX_PLATFORM_SETBUF_MACRO */

/*
 * The function pointers for exit
 */
#if defined(IOTEX_PLATFORM_EXIT_ALT)
extern void (*iotex_exit)( int status );

/**
 * \brief             This function dynamically configures the exit
 *                    function that is called when the iotex_exit()
 *                    function is invoked by the library.
 *
 * \param exit_func   The \c exit function implementation.
 *
 * \return            \c 0 on success.
 */
int iotex_platform_set_exit( void (*exit_func)( int status ) );
#else
#if defined(IOTEX_PLATFORM_EXIT_MACRO)
#define iotex_exit   IOTEX_PLATFORM_EXIT_MACRO
#else
#define iotex_exit   exit
#endif /* IOTEX_PLATFORM_EXIT_MACRO */
#endif /* IOTEX_PLATFORM_EXIT_ALT */

/*
 * The default exit values
 */
#if defined(IOTEX_PLATFORM_STD_EXIT_SUCCESS)
#define IOTEX_EXIT_SUCCESS IOTEX_PLATFORM_STD_EXIT_SUCCESS
#else
#define IOTEX_EXIT_SUCCESS 0
#endif
#if defined(IOTEX_PLATFORM_STD_EXIT_FAILURE)
#define IOTEX_EXIT_FAILURE IOTEX_PLATFORM_STD_EXIT_FAILURE
#else
#define IOTEX_EXIT_FAILURE 1
#endif

/*
 * The function pointers for reading from and writing a seed file to
 * Non-Volatile storage (NV) in a platform-independent way
 *
 * Only enabled when the NV seed entropy source is enabled
 */
#if defined(IOTEX_ENTROPY_NV_SEED)
#if !defined(IOTEX_PLATFORM_NO_STD_FUNCTIONS) && defined(IOTEX_FS_IO)
/* Internal standard platform definitions */
int iotex_platform_std_nv_seed_read( unsigned char *buf, size_t buf_len );
int iotex_platform_std_nv_seed_write( unsigned char *buf, size_t buf_len );
#endif

#if defined(IOTEX_PLATFORM_NV_SEED_ALT)
extern int (*iotex_nv_seed_read)( unsigned char *buf, size_t buf_len );
extern int (*iotex_nv_seed_write)( unsigned char *buf, size_t buf_len );

/**
 * \brief   This function allows configuring custom seed file writing and
 *          reading functions.
 *
 * \param   nv_seed_read_func   The seed reading function implementation.
 * \param   nv_seed_write_func  The seed writing function implementation.
 *
 * \return  \c 0 on success.
 */
int iotex_platform_set_nv_seed(
            int (*nv_seed_read_func)( unsigned char *buf, size_t buf_len ),
            int (*nv_seed_write_func)( unsigned char *buf, size_t buf_len )
            );
#else
#if defined(IOTEX_PLATFORM_NV_SEED_READ_MACRO) && \
    defined(IOTEX_PLATFORM_NV_SEED_WRITE_MACRO)
#define iotex_nv_seed_read    IOTEX_PLATFORM_NV_SEED_READ_MACRO
#define iotex_nv_seed_write   IOTEX_PLATFORM_NV_SEED_WRITE_MACRO
#else
#define iotex_nv_seed_read    iotex_platform_std_nv_seed_read
#define iotex_nv_seed_write   iotex_platform_std_nv_seed_write
#endif
#endif /* IOTEX_PLATFORM_NV_SEED_ALT */
#endif /* IOTEX_ENTROPY_NV_SEED */

#if !defined(IOTEX_PLATFORM_SETUP_TEARDOWN_ALT)

/**
 * \brief   The platform context structure.
 *
 * \note    This structure may be used to assist platform-specific
 *          setup or teardown operations.
 */
typedef struct iotex_platform_context
{
    char dummy; /**< A placeholder member, as empty structs are not portable. */
}
iotex_platform_context;

#else
#include "include/platform_alt.h"
#endif /* !IOTEX_PLATFORM_SETUP_TEARDOWN_ALT */

/**
 * \brief   This function performs any platform-specific initialization
 *          operations.
 *
 * \note    This function should be called before any other library functions.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 * \return  \c 0 on success.
 */
int iotex_platform_setup( iotex_platform_context *ctx );
/**
 * \brief   This function performs any platform teardown operations.
 *
 * \note    This function should be called after every other Mbed TLS module
 *          has been correctly freed using the appropriate free function.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 */
void iotex_platform_teardown( iotex_platform_context *ctx );

#ifdef __cplusplus
}
#endif

#endif /* platform.h */
