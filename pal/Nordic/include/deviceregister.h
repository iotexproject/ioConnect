#ifndef __IOCONNECT_PAL_DEVREG_H__
#define __IOCONNECT_PAL_DEVREG_H__

int iotex_pal_device_register_init(char *deviceDID, char *deviceDIDDoc, unsigned int sign_kID);
int iotex_pal_device_register_loop(void);

#endif
