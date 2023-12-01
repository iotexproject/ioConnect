#ifndef PSA_CRYPTO_PLATFORM_H
#define PSA_CRYPTO_PLATFORM_H

#include "include/iotex/build_info.h"
#include "include/iotex/config_psa.h"

/* PSA requires several types which C99 provides in stdint.h. */
#include <stdint.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*
 * When IOTEX_PSA_CRYPTO_SPM is defined, the code is being built for SPM
 * (Secure Partition Manager) integration which separates the code into two
 * parts: NSPE (Non-Secure Processing Environment) and SPE (Secure Processing
 * Environment). When building for the SPE, an additional header file should be
 * included.
 */
#if defined(IOTEX_PSA_CRYPTO_SPM)
#define PSA_CRYPTO_SECURE 1
#include "include/iotex/crypto_spe.h"
#endif // IOTEX_PSA_CRYPTO_SPM

#if defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG)
typedef struct {
    uintptr_t opaque[2];
} iotex_psa_external_random_context_t;
#endif /* IOTEX_PSA_CRYPTO_EXTERNAL_RNG */

#endif /* PSA_CRYPTO_PLATFORM_H */
