#ifndef __IOTEX_PAL_DEVICE_REGISTER__
#define __IOTEX_PAL_DEVICE_REGISTER__

#include <stdint.h>
#include "deviceregister_config.h"

void iotex_pal_sprout_device_register_start(char *did, char *diddoc);
void iotex_pal_sprout_device_register_stop(void);

#endif