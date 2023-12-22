#ifndef ED_DSA_H
#define ED_DSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int uECC_ed25519_sign(const uint8_t *private_key, const uint8_t *public_key, const uint8_t *message, unsigned message_len, uint8_t *signature);
int uECC_ed25519_verify(const uint8_t *public_key, const uint8_t *message, unsigned message_len, const uint8_t *signature); 

#ifdef __cplusplus
}
#endif

#endif
