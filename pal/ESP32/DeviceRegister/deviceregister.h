#ifndef __IOTEX_PAL_DEVICE_REGISTER__
#define __IOTEX_PAL_DEVICE_REGISTER__

#include <stdint.h>
#include "deviceregister_config.h"

char * iotex_pal_device_register_did_upload_prepare(char *did, uint32_t keyid);
char * iotex_pal_device_register_diddoc_upload_prepare(char *diddoc, uint32_t keyid);
char * iotex_pal_device_register_signature_response_prepare(char *buf, uint32_t keyid);

void iotex_pal_sprout_device_register_start(char *did, char *diddoc);
void iotex_pal_sprout_device_register_stop(void);

#endif