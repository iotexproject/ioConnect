#ifndef IOTEX_PLATFORM_TIME_H
#define IOTEX_PLATFORM_TIME_H

#include "include/iotex/build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The time_t datatype
 */
#if defined(IOTEX_PLATFORM_TIME_TYPE_MACRO)
typedef IOTEX_PLATFORM_TIME_TYPE_MACRO iotex_time_t;
#else
/* For time_t */
#include <time.h>
typedef time_t iotex_time_t;
#endif /* IOTEX_PLATFORM_TIME_TYPE_MACRO */

/*
 * The function pointers for time
 */
#if defined(IOTEX_PLATFORM_TIME_ALT)
extern iotex_time_t (*iotex_time)( iotex_time_t* time );

/**
 * \brief   Set your own time function pointer
 *
 * \param   time_func   the time function implementation
 *
 * \return              0
 */
int iotex_platform_set_time( iotex_time_t (*time_func)( iotex_time_t* time ) );
#else
#if defined(IOTEX_PLATFORM_TIME_MACRO)
#define iotex_time    IOTEX_PLATFORM_TIME_MACRO
#else
#define iotex_time   time
#endif /* IOTEX_PLATFORM_TIME_MACRO */
#endif /* IOTEX_PLATFORM_TIME_ALT */

#ifdef __cplusplus
}
#endif

#endif /* platform_time.h */
