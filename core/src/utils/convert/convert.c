#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char _str2Hex(char c)
{
    if (c >= '0' && c <= '9') {
        return (c - '0');
    }

    if (c >= 'a' && c <= 'z') {
        return (c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'Z') {
        return (c -'A' + 10);
    }
    return c;
}

#if 0
void iotex_utils_convert_hex_to_str(const unsigned char *hex, size_t hex_size, char *output) 
{
    int i, j;
    const char hexmap[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };    

    for (i = 0, j = 0; i < hex_size; i++) {
        output[j++] = hexmap[hex[i] >> 4];    
        output[j++] = hexmap[hex[i] & 0x0F];
    }

    output[j] = 0;    
}
#else
void iotex_utils_convert_hex_to_str(const unsigned char *hex, size_t hex_size, char *output) 
{
    for (size_t i = 0; i < hex_size; ++i) {
        sprintf(output + (i * 2), "%02x", hex[i]);
    }

    output[hex_size * 2] = '\0';
}
#endif

int iotex_utils_convert_str_to_hex(char *str, char *hex) 
{
    int j = 0;

    for(int i = 0, j = 0; j < (strlen(str)>>1) ; i++,j++)
    {
        hex[j] = (_str2Hex(str[i]) <<4);
        i++;
        hex[j] |= _str2Hex(str[i]);
    }

    return j; 
}