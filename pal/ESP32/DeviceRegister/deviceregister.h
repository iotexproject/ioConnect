#ifndef __IOTEX_PAL_DEVICE_REGISTER__
#define __IOTEX_PAL_DEVICE_REGISTER__

#include "include/psa/crypto.h"

#define IOTEX_PAL_DEVICE_REGISTER_COMMAND_DID_UPLOAD            'H'
#define IOTEX_PAL_DEVICE_REGISTER_COMMAND_DIDDOC_UPLOAD         'B'
#define IOTEX_PAL_DEVICE_REGISTER_COMMAND_SIGNATURE_RESPONSE    'S'

char * iotex_pal_device_register_did_upload_prepare(char *did, psa_key_id_t keyid);
char * iotex_pal_device_register_diddoc_upload_prepare(char *diddoc, psa_key_id_t keyid);
char * iotex_pal_device_register_signature_response_prepare(char *buf, psa_key_id_t keyid);

#endif