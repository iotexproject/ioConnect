#ifndef __ACC_DRIVE_RSA_H__
#define __ACC_DRIVE_RSA_H__

#include "include/common.h"

#include "include/iotex/platform.h"
#include "include/server/crypto/psa_crypto_rsa.h"

psa_status_t iotex_crypto_acceleration_asymmetric_encrypt( const psa_key_attributes_t *attributes,
                                             const uint8_t *key_buffer,
                                             size_t key_buffer_size,
                                             psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             const uint8_t *salt,
                                             size_t salt_length,
                                             uint8_t *output,
                                             size_t output_size,
                                             size_t *output_length );
psa_status_t iotex_crypto_acceleration_asymmetric_decrypt( const psa_key_attributes_t *attributes,
                                             const uint8_t *key_buffer,
                                             size_t key_buffer_size,
                                             psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             const uint8_t *salt,
                                             size_t salt_length,
                                             uint8_t *output,
                                             size_t output_size,
                                             size_t *output_length );
#endif



