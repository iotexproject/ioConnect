/**********************************************************************
 *
 * File name    : base64.h
 * Function     : base64 encoding and decoding of data or file.
 * Created time : 2020-08-04
 *
 *********************************************************************/

#ifndef BASE64_H
#define BASE64_H

#define BASE64_ENCODE_GETLENGTH(x) (((x + 3 - 1) / 3) * 4) + 1

int base64_encode(const char *indata, size_t inlen, char *outdata, size_t *outlen);
int base64_decode(const char *indata, size_t inlen, char *outdata, size_t *outlen);

int base64url_encode(const char *indata, size_t inlen, char *outdata, size_t *outlen);
int base64url_decode(const char *indata, size_t inlen, char *outdata, size_t *outlen);

char * base64url_malloc(size_t *len);

char *base64_encode_automatic( const char *buf, size_t buf_len );
char *base64_decode_automatic( const char *inbuf, size_t inbuf_len, size_t *out_len);

#endif // BASE64_H
