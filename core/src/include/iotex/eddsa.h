#ifndef IOTEX_EDDSA_H
#define IOTEX_EDDSA_H

#include "include/iotex/build_info.h"

#include "include/iotex/ecp.h"
#include "include/iotex/md.h"

#ifdef __cplusplus
extern "C" {
#endif

int iotex_eddsa_sign( uint16_t type, 
                            const uint8_t *key_buffer, size_t key_buffer_size, 
                            const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t *signature_length );
int iotex_eddsa_verify( psa_key_type_t type,
                          const uint8_t *key_buffer, size_t key_buffer_size,
                          const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_length );                            

#ifdef __cplusplus
}
#endif

#endif /* eddsa.h */
