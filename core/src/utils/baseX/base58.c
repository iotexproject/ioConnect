#include <stdlib.h>
#include <string.h>

#include "include/server/crypto.h"
#include "include/jose/jwk.h"
#include "include/dids/did/did.h"
#include "include/dids/did/did_key.h"
#include "include/utils/cJSON/cJSON.h"
#include "include/utils/baseX/base58.h"

char *base58_encode(const unsigned char *src, int len)
{
    const char encoding_table[58] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    char *out = NULL, *ptr = NULL;
    unsigned int size, high, zero = 0;
    int i, j, carry;

    if (src == NULL)
        return NULL;

    while (zero < len && *(src + zero) == 0) {
        ++zero;
    }

    size = (len - zero) * 138 / 100;

    unsigned char buff[size + 1];
    memset(buff, 0, size + 1);

    for (i = zero, high = size; i < len; ++i, high = j) {
        for (carry = *(src + i), j = size; (j > high) || carry; --j) {
            carry += 256 * buff[j];
            *(buff + j) = carry % 58;
            carry /= 58;

            if (!j) break;
        }
    }

    for (j = 0; j < (size + 1) && !buff[j]; ++j);
        
    out = malloc((zero + size - j + 1) * sizeof(char));
    ptr = out + zero;

    if (zero) {
        memset(out, '1', zero);
    }

    for (; j < size + 1; ++j) {
        *ptr++ = encoding_table[buff[j]];
    }

    *ptr = 0;
    return out;
}

unsigned char *base58_decode(const char *src, int len)
{
    const char decoding_table[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1,
        -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
        -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    unsigned char *out;
    unsigned int size, buff = 1;
    int i, j, carry;

    if (src == NULL)
        return NULL;

    size = len * 138 / 100;
    out = malloc((size + 1) * sizeof(unsigned char));
    *out = 0;

    for (i = 0; i < len; i++) {
        const unsigned char c = *src++;
        carry = decoding_table[c];

        if (carry == -1)
            return NULL;

        for (j = 0; j < buff; j++) {
            carry += out[j] * 58;
            *(out + j) = carry & 0xff;
            carry >>= 8;
        }

        while (carry > 0) {
            out[buff++] = carry & 0xff;
            carry >>= 8;
        }
    }

    while (len-- && *src++ == '1')
        out[buff++] = 0;

    for (i = buff - 1, j = (buff >> 1) + (buff & 1); i >= j; i--) {
        int t = out[i];
        out[i] = out[buff - i - 1];
        out[buff - i - 1] = t;
    }

    out[buff] = 0;
    return out;
}