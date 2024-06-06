#ifndef __IOTEX_PAL_DEVICE_REGISTER__
#define __IOTEX_PAL_DEVICE_REGISTER__

#include <stdint.h>

typedef enum
{
    PAL_SPROUT_DEVICE_REGISTER_MODE_SERIAL  = 0x00,
    PAL_SPROUT_DEVICE_REGISTER_MODE_HTTPS   = 0x01,
} device_register_mode;

#define IOTEX_PAL_DEVICE_REGISTER_COMMAND_DID_UPLOAD            'H'
#define IOTEX_PAL_DEVICE_REGISTER_COMMAND_DIDDOC_UPLOAD         'B'
#define IOTEX_PAL_DEVICE_REGISTER_COMMAND_SIGNATURE_RESPONSE    'S'

char * iotex_pal_device_register_did_upload_prepare(char *did, uint32_t keyid);
char * iotex_pal_device_register_diddoc_upload_prepare(char *diddoc, uint32_t keyid);
char * iotex_pal_device_register_signature_response_prepare(char *buf, uint32_t keyid);

void iotex_pal_sprout_device_register_start(char *did, char *diddoc, device_register_mode mode);
void iotex_pal_sprout_device_register_stop(void);

#endif