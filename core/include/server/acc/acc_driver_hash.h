#ifndef __ACC_DRIVE_HASH_H__
#define __ACC_DRIVE_HASH_H__

#include "include/common.h"

#include "include/iotex/platform.h"
#include "include/server/crypto/psa_crypto_hash.h"

psa_status_t iotex_crypto_acceleration_hash_setup(iotex_psa_hash_operation_t *operation, psa_algorithm_t alg );
psa_status_t iotex_crypto_acceleration_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length);
psa_status_t iotex_crypto_acceleration_hash_update(iotex_psa_hash_operation_t *operation, const uint8_t *input, size_t input_length );
psa_status_t iotex_crypto_acceleration_hash_finish(iotex_psa_hash_operation_t *operation, uint8_t *hash, size_t hash_size, size_t *hash_length );
psa_status_t iotex_crypto_acceleration_hash_abort( iotex_psa_hash_operation_t *operation );

#endif



