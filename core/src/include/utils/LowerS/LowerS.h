#ifndef __IOTEX_LOWERS_H__
#define __IOTEX_LOWERS_H__

#ifdef __cplusplus
extern "C" {
#endif

void iotex_utils_secp256k1_eth_lower_s_init(void);
void iotex_utils_secp256k1_eth_lower_s_calc(char *s, char *out);

#ifdef __cplusplus
}
#endif

#endif /* __IOTEX_LOWERS_H__ */
