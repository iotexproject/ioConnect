#ifndef __ACC_DRIVE_AES_H__
#define __ACC_DRIVE_AES_H__

#include "include/common.h"

#include "include/iotex/platform.h"
#include "include/server/crypto/psa_crypto_cipher.h"

psa_status_t iotex_crypto_acceleration_cipher_setup( iotex_psa_cipher_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, uint8_t cipher_operation );
psa_status_t iotex_crypto_acceleration_cipher_set_iv( iotex_psa_cipher_operation_t *operation, const uint8_t *iv, size_t iv_length );
psa_status_t iotex_crypto_acceleration_cipher_update( iotex_psa_cipher_operation_t *operation, const uint8_t *input, size_t input_length, uint8_t *output, size_t output_size, size_t *output_length );
psa_status_t iotex_crypto_acceleration_cipher_finish( iotex_psa_cipher_operation_t *operation, uint8_t *output, size_t output_size, size_t *output_length );
psa_status_t iotex_crypto_acceleration_cipher_abort( iotex_psa_cipher_operation_t *operation );
psa_status_t iotex_crypto_acceleration_cipher_encrypt( const psa_key_attributes_t *attributes,
														const uint8_t *key_buffer, size_t key_buffer_size,
														psa_algorithm_t alg,
														const uint8_t *iv, size_t iv_length,
														const uint8_t *input, size_t input_length,
														uint8_t *output, size_t output_size, size_t *output_length );
psa_status_t iotex_crypto_acceleration_cipher_decrypt( const psa_key_attributes_t *attributes,
														const uint8_t *key_buffer, size_t key_buffer_size,
														psa_algorithm_t alg,
														const uint8_t *input, size_t input_length,
														uint8_t *output, size_t output_size, size_t *output_length );

#endif



