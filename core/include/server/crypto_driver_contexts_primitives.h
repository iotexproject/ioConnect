#ifndef PSA_CRYPTO_DRIVER_CONTEXTS_PRIMITIVES_H
#define PSA_CRYPTO_DRIVER_CONTEXTS_PRIMITIVES_H

#include "include/server/crypto_driver_common.h"

/* Include the context structure definitions for the Mbed TLS software drivers */
#include "include/server/crypto_builtin_primitives.h"

/* Define the context to be used for an operation that is executed through the
 * PSA Driver wrapper layer as the union of all possible driver's contexts.
 *
 * The union members are the driver's context structures, and the member names
 * are formatted as `'drivername'_ctx`. This allows for procedural generation
 * of both this file and the content of psa_crypto_driver_wrappers.c */

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    iotex_psa_hash_operation_t iotex_ctx;
#if defined(PSA_CRYPTO_DRIVER_TEST)
    iotex_transparent_test_driver_hash_operation_t test_driver_ctx;
#endif
} psa_driver_hash_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    iotex_psa_cipher_operation_t iotex_ctx;
#if defined(PSA_CRYPTO_DRIVER_TEST)
    iotex_transparent_test_driver_cipher_operation_t transparent_test_driver_ctx;
    iotex_opaque_test_driver_cipher_operation_t opaque_test_driver_ctx;
#endif
} psa_driver_cipher_context_t;

#endif /* PSA_CRYPTO_DRIVER_CONTEXTS_PRIMITIVES_H */
/* End of automatically generated file. */
