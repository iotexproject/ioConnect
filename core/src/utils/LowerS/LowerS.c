#include <stdio.h>
#include <math.h>
#include <string.h>

#define MAXN 200

struct BigNum {
    int num[MAXN];
    int len;
};
struct BigNum Lower_S;
struct BigNum Max_s ;

//a > b return 1, a == b return 0; a < b return -1;
int Comp(struct BigNum *a, struct BigNum *b) {
    int i;
    if (a->len != b->len)
        return (a->len > b->len) ? 1 : -1;

    for (i = a->len - 1; i >= 0; i--) {
        if (a->num[i] != b->num[i])
            return (a->num[i] > b->num[i]) ? 1 : -1;
    }

    return 0;
}

struct BigNum Sub(struct BigNum *a, struct BigNum *b) {
    struct BigNum c;
    int i, len;
    len = (a->len > b->len) ? a->len : b->len;
    memset(c.num, 0, sizeof(c.num));
    for (i = 0; i < len; i++) {
        c.num[i] += (a->num[i] - b->num[i]);
        if (c.num[i] < 0) {
            c.num[i] += 16;
            c.num[i + 1]--;
        }
    }
    while (c.num[len - 1] == 0 && len > 1)
        len--;
    c.len = len;
    return c;
}


// void print(struct BigNum *a) { 
//     int i;
//     for (i = a->len - 1; i >= 0; i--)
//         LOG_INF("%01x", (unsigned char)a->num[i]);
//     LOG_INF("\n");
// }

static char str2Hex(char c)
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

int hexStr2Bin(char *str, char *bin) {
    int i,j;
    for(i = 0,j = 0; j < (strlen(str)>>1) ; i++,j++)
    {
        bin[j] = (str2Hex(str[i]) <<4);
        i++;
        bin[j] |= str2Hex(str[i]);
    }   
    return j; 
}

void printBuf(struct BigNum *a, char *buf) {
    int i, j;
//    LOG_INF("a->len: %d\n", a->len);
    if (a->len < 64) a->len = 64;
    for (i = a->len, j = 0; j < (a->len >> 1) ; i--,j++) {
        buf[j] = (str2Hex(a->num[i - 1]) << 4);
        i--;
        buf[j] |= str2Hex(a->num[i - 1]);
    }
}

void Init(struct BigNum *a, char *s, int *tag) { 
    memset(a->num, 0, sizeof(a->num));
    int i = 0, j = strlen(s);
    if (s[0] == '-') {
        j--;
        i++;
        *tag *= -1;
    }
    a->len = j;
    for (; s[i] != '\0'; i++, j--){
        //a->num[j - 1] =(str2Hex(s[i++])<<4);
        a->num[j - 1] |=str2Hex(s[i]);
    }
}

void InitBinary(struct BigNum *a, char *binary, int  len) {
    memset(a->num, 0, sizeof(a->num));
    int i = 0, j = (len<<1);
    a->len = j;
    for (; i != len; i++, j--){
        //a->num[j - 1] =(str2Hex(s[i++])<<4);
        a->num[j - 1] =((binary[i]&0xF0)>>4);
        j--;
        a->num[j - 1] =(binary[i]&0x0F);
    }
}

void InitLowsCalc(void) {
    int tag = 1;
    Init(&Lower_S, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", &tag);
    Init(&Max_s, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", &tag);    
}

/*
    s : signature s in binary, out : low-s value in binary
*/
void LowsCalc(char *s, char *out) {   
    struct BigNum a;

    InitBinary(&a, s, 32);
    if (Comp((struct BigNum *)&Lower_S, &a) < 0) {
        a = Sub((struct BigNum *)&Max_s , &a);
        printBuf(&a, out);
    }
}
