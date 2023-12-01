#ifndef IOTEX_BUILD_INFO_H
#define IOTEX_BUILD_INFO_H

/**
 * The version number x.y.z is split into three parts.
 * Major, Minor, Patchlevel
 */
#define IOTEX_VERSION_MAJOR  0
#define IOTEX_VERSION_MINOR  9
#define IOTEX_VERSION_PATCH  0

/**
 * The single version number has the following structure:
 *    MMNNPP00
 *    Major version | Minor version | Patch version
 */
#define IOTEX_VERSION_NUMBER         0x00090000
#define IOTEX_VERSION_STRING         "0.9.0"
#define IOTEX_VERSION_STRING_FULL    "iotex psa layer 0.9.0"

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#if !defined(IOTEX_CONFIG_FILE)
#include "include/config/iotex_layer_config.h"
#else
#include IOTEX_CONFIG_FILE
#endif

/* Target and application specific configurations
 *
 * Allow user to override any previous default.
 *
 */
#if defined(IOTEX_USER_CONFIG_FILE)
#include IOTEX_USER_CONFIG_FILE
#endif

#if defined(IOTEX_PK_C) && defined(IOTEX_USE_PSA_CRYPTO)
#define IOTEX_PK_WRITE_C
#endif

#if defined(IOTEX_PSA_CRYPTO_CONFIG)
#include "include/iotex/config_psa.h"
#endif

//#include "include/iotex/check_config.h"
#include "include/iotex/check_config.h"

#endif /* IOTEX_BUILD_INFO_H */
