#ifndef __IOCONNECT_PAL_JOSE_H__
#define __IOCONNECT_PAL_JOSE_H__

char *iotex_pal_jose_device_did_get(void);
char *iotex_pal_jose_device_kid_get(void);
char *iotex_pal_jose_device_kakid_get(void);

int iotex_pal_jose_generate_jwk(void);
char *iotex_pal_jose_generate_diddoc(void);

#endif
