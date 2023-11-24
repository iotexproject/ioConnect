cmake_minimum_required(VERSION 3.16)

if(ESP_PLATFORM)
	string(REPLACE "\\" "/" ESP_IDF_PATH $ENV{IDF_PATH})
	idf_component_register(SRCS "DeviceConnect_Core.c"
							"crypto/aes_decrypt.c"
							"crypto/aes_encrypt.c"
							"crypto/cbc_mode.c"
							"crypto/ccm_mode.c"
							"crypto/cmac_mode.c"
							"crypto/ctr_mode.c"
							"crypto/ctr_prng.c"
							"crypto/ecc_dh.c"
							"crypto/ecc_dsa.c"
							"crypto/ecc_platform_specific.c"
							"crypto/ecc.c"
							"crypto/hmac_prng.c"
							"crypto/hmac.c"
							"crypto/sha256.c"
							"crypto/utils.c"
							"psa/cipher_wrap.c"
							"psa/psa_crypto_cipher.c"
							"psa/psa_crypto_client.c"
							"psa/psa_crypto_driver_wrappers.c"
							"psa/psa_crypto_ecp.c"
							"psa/psa_crypto_hash.c"
							"psa/psa_crypto_rsa.c"
							"psa/psa_crypto_porting.c"
							"psa/psa_crypto_slot_management.c"
							"psa/psa_crypto.c"
							"psa/psa_crypto_storage.c"
							"psa/psa_its_file.c"
							"psa/psa_its_flash.c"
							"psa/psa_its_nvs.c"
							"utils/iotex_dev_access.c"
							"utils/cJSON/cJSON.c"
							"utils/keccak256/keccak256.c"
							"utils/ProtoBuf/devnet_upload.pb.c"
							"utils/ProtoBuf/header.pb.c"
							"utils/ProtoBuf/payload.pb.c"
							"utils/ProtoBuf/packconfirm.pb.c"
							"utils/ProtoBuf/pb_common.c"
							"utils/ProtoBuf/pb_decode.c"
							"utils/ProtoBuf/pb_encode.c"
							"utils/base64/base64.c"
							"utils/LowerS/LowerS.c"
							"hal/flash/flash_common.c"
							"hal/flash/soc/esp32/flash.c"
							"hal/nvs/nvs_common.c"
							"hal/nvs/soc/esp32/nvs_esp32.c"
                    INCLUDE_DIRS "." 
					        "include" 
							"include/utils" "include/backends" 
							"${ESP_IDF_PATH}/components/nvs_flash/include" 
							"${ESP_IDF_PATH}/components/esp_partition/include"
                    REQUIRES mbedtls)

	target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")  
	return()
endif()

# If you set any CMAKE_ variables, that can go here.
# (But usually don't do this, except maybe for C++ standard)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(
  DeviceConnectSDK
  VERSION 1.0
  LANGUAGES C CXX
)

# Add a static library DeviceConnectSDK
add_library(DeviceConnectSDK STATIC)

target_sources(DeviceConnectSDK 
  PRIVATE
    DeviceConnect_Core.c
	crypto/aes_decrypt.c
	crypto/aes_encrypt.c
	crypto/cbc_mode.c
	crypto/ccm_mode.c
	crypto/cmac_mode.c
	crypto/ctr_mode.c
	crypto/ctr_prng.c
	crypto/ecc_dh.c
	crypto/ecc_dsa.c
	crypto/ecc_platform_specific.c
	crypto/ecc.c
	crypto/hmac_prng.c
	crypto/hmac.c
	crypto/sha256.c
	crypto/utils.c
	psa/cipher_wrap.c
	psa/psa_crypto_cipher.c
	psa/psa_crypto_client.c
	psa/psa_crypto_driver_wrappers.c
	psa/psa_crypto_ecp.c
	psa/psa_crypto_hash.c
	psa/psa_crypto_rsa.c
	psa/psa_crypto_porting.c
	psa/psa_crypto_slot_management.c
	psa/psa_crypto.c
	psa/psa_crypto_storage.c
	psa/psa_its_file.c
	psa/psa_its_flash.c
	psa/psa_its_nvs.c
	utils/iotex_dev_access.c
	utils/cJSON/cJSON.c
	utils/keccak256/keccak256.c
	utils/ProtoBuf/devnet_upload.pb.c
	utils/ProtoBuf/header.pb.c
	utils/ProtoBuf/payload.pb.c
	utils/ProtoBuf/packconfirm.pb.c
	utils/ProtoBuf/pb_common.c
	utils/ProtoBuf/pb_decode.c
	utils/ProtoBuf/pb_encode.c
	utils/base64/base64.c
	utils/LowerS/LowerS.c	
)