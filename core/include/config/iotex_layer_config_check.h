#if defined(IOTEX_PSA_ITS_NVS_C) && defined(CONFIG_PLATFORM_ARDUINO)
#error "Currently NVS does not support Arduino development platform, please select FLASH mode"
#endif

#if defined(CONFIG_PSA_CRYPTO_BACKENDS_MBEDTLS) && defined(CONFIG_PLATFORM_ARDUINO)
#error "Currently mBedtls does not support Arduino development platform, please select TinyCrypt Backend"
#endif

#if defined(CONFIG_PSA_CRYPTO_BACKENDS_MBEDTLS) && defined(CONFIG_PLATFORM_ESPRESSIF)
#error "Currently mBedtls does not support ESPRESSIF development platform, please select TinyCrypt Backend"
#endif