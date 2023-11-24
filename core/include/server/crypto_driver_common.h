#ifndef PSA_CRYPTO_DRIVER_COMMON_H
#define PSA_CRYPTO_DRIVER_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* Include type definitions (psa_status_t, psa_algorithm_t,
 * psa_key_type_t, etc.) and macros to build and analyze values
 * of these types. */
#include "include/server/crypto_types.h"
#include "include/server/crypto_values.h"
/* Include size definitions which are used to size some arrays in operation
 * structures. */
#include "include/server/crypto_sizes.h"

/** For encrypt-decrypt functions, whether the operation is an encryption
 * or a decryption. */
typedef enum {
    PSA_CRYPTO_DRIVER_DECRYPT,
    PSA_CRYPTO_DRIVER_ENCRYPT
} psa_encrypt_or_decrypt_t;

#endif /* PSA_CRYPTO_DRIVER_COMMON_H */
