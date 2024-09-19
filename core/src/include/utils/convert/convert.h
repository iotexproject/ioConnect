#ifndef __IOTEX_UTILS_CONVERT_H__
#define __IOTEX_UTILS_CONVERT_H__

void iotex_utils_convert_hex_to_str(const unsigned char *hex, size_t hex_size, char *output);
int iotex_utils_convert_str_to_hex(char *str, char *hex);

#endif

