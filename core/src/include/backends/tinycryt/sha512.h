#ifndef __TC_SHA512_H__
#define __TC_SHA512_H__

#include <stddef.h>
#include <stdint.h>

#include "include/backends/tinycryt/fixedint.h"

/* state */
struct tc_sha512_state_struct {
    uint64_t  length, state[8];
    size_t curlen;
    unsigned char buf[128];
};

typedef struct tc_sha512_state_struct *TCSha512State_t;

int tc_sha512_init(TCSha512State_t s);
int tc_sha512_final(TCSha512State_t s, uint8_t *digest);
int tc_sha512_update(TCSha512State_t s, const uint8_t *data, size_t datalen);
int tc_sha512(const uint8_t *message, size_t messagelen, unsigned char *digest);

#endif
