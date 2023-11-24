/**********************************************************************
 *
 * File name    : base64.h
 * Function     : base64 encoding and decoding of data or file.
 * Created time : 2020-08-04
 *
 *********************************************************************/

#ifndef BASE64_H
#define BASE64_H

//base64编码
int base64_encode(const char *indata, int inlen, char *outdata, int *outlen);
//base64解码
int base64_decode(const char *indata, int inlen, char *outdata, int *outlen);
//base64编码文件
int base64_encode_file(const char *src, const char *dst);
//base64解码文件
int base64_decode_file(const char *src, const char *dst);

#endif // BASE64_H
