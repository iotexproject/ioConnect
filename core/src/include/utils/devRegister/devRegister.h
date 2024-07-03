#ifndef __DEV_REGISTER_H__
#define __DEV_REGISTER_H__

#include <stdint.h>

#include "include/psa/crypto.h"

char * iotex_utils_device_register_did_upload_prepare(char *did, psa_key_id_t keyid);
char * iotex_utils_device_register_diddoc_upload_prepare(char *diddoc, psa_key_id_t keyid);
char * iotex_utils_device_register_signature_response_prepare(char *buf, psa_key_id_t keyid);


#endif