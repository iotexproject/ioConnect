#ifndef _BASE58_H
#define _BASE58_H


#include <stddef.h>
#include <string.h>
#include <malloc.h>


char *base58_encode(const unsigned char *src, int len);
unsigned char *base58_decode(const char *src, int len);


#endif /*_BASE58_H*/