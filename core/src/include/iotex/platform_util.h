#ifndef IOTEX_PLATFORM_UTIL_H
#define IOTEX_PLATFORM_UTIL_H

#include "include/iotex/build_info.h"

#include <stddef.h>
#if defined(IOTEX_HAVE_TIME_DATE)
#include "include/iotex/platform_time.h"
#include <time.h>
#endif /* IOTEX_HAVE_TIME_DATE */

#ifdef __cplusplus
extern "C" {
#endif

/* Internal macros meant to be called only from within the library. */
#define IOTEX_INTERNAL_VALIDATE_RET( cond, ret )  do { } while( 0 )
#define IOTEX_INTERNAL_VALIDATE( cond )           do { } while( 0 )

/* Internal helper macros for deprecating API constants. */
#if !defined(IOTEX_DEPRECATED_REMOVED)
#if defined(IOTEX_DEPRECATED_WARNING)
#define IOTEX_DEPRECATED __attribute__((deprecated))
IOTEX_DEPRECATED typedef char const * iotex_deprecated_string_constant_t;
#define IOTEX_DEPRECATED_STRING_CONSTANT( VAL )       \
    ( (iotex_deprecated_string_constant_t) ( VAL ) )
IOTEX_DEPRECATED typedef int iotex_deprecated_numeric_constant_t;
#define IOTEX_DEPRECATED_NUMERIC_CONSTANT( VAL )       \
    ( (iotex_deprecated_numeric_constant_t) ( VAL ) )
#else /* IOTEX_DEPRECATED_WARNING */
#define IOTEX_DEPRECATED
#define IOTEX_DEPRECATED_STRING_CONSTANT( VAL ) VAL
#define IOTEX_DEPRECATED_NUMERIC_CONSTANT( VAL ) VAL
#endif /* IOTEX_DEPRECATED_WARNING */
#endif /* IOTEX_DEPRECATED_REMOVED */

/* Implementation of the check-return facility.
 * See the user documentation in iotex_config.h.
 *
 * Do not use this macro directly to annotate function: instead,
 * use one of IOTEX_CHECK_RETURN_CRITICAL or IOTEX_CHECK_RETURN_TYPICAL
 * depending on how important it is to check the return value.
 */
#if !defined(IOTEX_CHECK_RETURN)
#if defined(__GNUC__)
#define IOTEX_CHECK_RETURN __attribute__((__warn_unused_result__))
#elif defined(_MSC_VER) && _MSC_VER >= 1700
#include <sal.h>
#define IOTEX_CHECK_RETURN _Check_return_
#else
#define IOTEX_CHECK_RETURN
#endif
#endif

/** Critical-failure function
 *
 * This macro appearing at the beginning of the declaration of a function
 * indicates that its return value should be checked in all applications.
 * Omitting the check is very likely to indicate a bug in the application
 * and will result in a compile-time warning if #IOTEX_CHECK_RETURN
 * is implemented for the compiler in use.
 *
 * \note  The use of this macro is a work in progress.
 *        This macro may be added to more functions in the future.
 *        Such an extension is not considered an API break, provided that
 *        there are near-unavoidable circumstances under which the function
 *        can fail. For example, signature/MAC/AEAD verification functions,
 *        and functions that require a random generator, are considered
 *        return-check-critical.
 */
#define IOTEX_CHECK_RETURN_CRITICAL IOTEX_CHECK_RETURN

/** Ordinary-failure function
 *
 * This macro appearing at the beginning of the declaration of a function
 * indicates that its return value should be generally be checked in portable
 * applications. Omitting the check will result in a compile-time warning if
 * #IOTEX_CHECK_RETURN is implemented for the compiler in use and
 * #IOTEX_CHECK_RETURN_WARNING is enabled in the compile-time configuration.
 *
 * You can use #IOTEX_IGNORE_RETURN to explicitly ignore the return value
 * of a function that is annotated with #IOTEX_CHECK_RETURN.
 *
 * \note  The use of this macro is a work in progress.
 *        This macro will be added to more functions in the future.
 *        Eventually this should appear before most functions returning
 *        an error code (as \c int in the \c iotex_xxx API or
 *        as ::psa_status_t in the \c psa_xxx API).
 */
#if defined(IOTEX_CHECK_RETURN_WARNING)
#define IOTEX_CHECK_RETURN_TYPICAL IOTEX_CHECK_RETURN
#else
#define IOTEX_CHECK_RETURN_TYPICAL
#endif

/** Benign-failure function
 *
 * This macro appearing at the beginning of the declaration of a function
 * indicates that it is rarely useful to check its return value.
 *
 * This macro has an empty expansion. It exists for documentation purposes:
 * a #IOTEX_CHECK_RETURN_OPTIONAL annotation indicates that the function
 * has been analyzed for return-check usefulness, whereas the lack of
 * an annotation indicates that the function has not been analyzed and its
 * return-check usefulness is unknown.
 */
#define IOTEX_CHECK_RETURN_OPTIONAL

/** \def IOTEX_IGNORE_RETURN
 *
 * Call this macro with one argument, a function call, to suppress a warning
 * from #IOTEX_CHECK_RETURN due to that function call.
 */
#if !defined(IOTEX_IGNORE_RETURN)
/* GCC doesn't silence the warning with just (void)(result).
 * (void)!(result) is known to work up at least up to GCC 10, as well
 * as with Clang and MSVC.
 *
 * https://gcc.gnu.org/onlinedocs/gcc-3.4.6/gcc/Non_002dbugs.html
 * https://stackoverflow.com/questions/40576003/ignoring-warning-wunused-result
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425#c34
 */
#define IOTEX_IGNORE_RETURN(result) ( (void) !( result ) )
#endif

/**
 * \brief       Securely zeroize a buffer
 *
 *              The function is meant to wipe the data contained in a buffer so
 *              that it can no longer be recovered even if the program memory
 *              is later compromised. Call this function on sensitive data
 *              stored on the stack before returning from a function, and on
 *              sensitive data stored on the heap before freeing the heap
 *              object.
 *
 *              It is extremely difficult to guarantee that calls to
 *              iotex_platform_zeroize() are not removed by aggressive
 *              compiler optimizations in a portable way. For this reason, Mbed
 *              TLS provides the configuration option
 *              IOTEX_PLATFORM_ZEROIZE_ALT, which allows users to configure
 *              iotex_platform_zeroize() to use a suitable implementation for
 *              their platform and needs
 *
 * \param buf   Buffer to be zeroized
 * \param len   Length of the buffer in bytes
 *
 */
void iotex_platform_zeroize( void *buf, size_t len );

#if defined(IOTEX_HAVE_TIME_DATE)
/**
 * \brief      Platform-specific implementation of gmtime_r()
 *
 *             The function is a thread-safe abstraction that behaves
 *             similarly to the gmtime_r() function from Unix/POSIX.
 *
 *             Mbed TLS will try to identify the underlying platform and
 *             make use of an appropriate underlying implementation (e.g.
 *             gmtime_r() for POSIX and gmtime_s() for Windows). If this is
 *             not possible, then gmtime() will be used. In this case, calls
 *             from the library to gmtime() will be guarded by the mutex
 *             iotex_threading_gmtime_mutex if IOTEX_THREADING_C is
 *             enabled. It is recommended that calls from outside the library
 *             are also guarded by this mutex.
 *
 *             If IOTEX_PLATFORM_GMTIME_R_ALT is defined, then Mbed TLS will
 *             unconditionally use the alternative implementation for
 *             iotex_platform_gmtime_r() supplied by the user at compile time.
 *
 * \param tt     Pointer to an object containing time (in seconds) since the
 *               epoch to be converted
 * \param tm_buf Pointer to an object where the results will be stored
 *
 * \return      Pointer to an object of type struct tm on success, otherwise
 *              NULL
 */
struct tm *iotex_platform_gmtime_r( const iotex_time_t *tt,
                                      struct tm *tm_buf );
#endif /* IOTEX_HAVE_TIME_DATE */

#ifdef __cplusplus
}
#endif

#endif /* IOTEX_PLATFORM_UTIL_H */
