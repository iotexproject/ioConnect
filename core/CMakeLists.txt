cmake_minimum_required(VERSION 3.16)

if(ESP_PLATFORM)
	string(REPLACE "\\" "/" ESP_IDF_PATH $ENV{IDF_PATH})
	idf_component_register(SRCS "src/DeviceConnect_Core.cpp"
							"src/crypto/aes_decrypt.c"
							"src/crypto/aes_encrypt.c"
							"src/crypto/cbc_mode.c"
							"src/crypto/ccm_mode.c"
							"src/crypto/cmac_mode.c"
							"src/crypto/ctr_mode.c"
							"src/crypto/ctr_prng.c"
							"src/crypto/ecc_dh.c"
							"src/crypto/ecc_dsa.c"
							"src/crypto/ecc_platform_specific.c"
							"src/crypto/ecc.c"
							"src/crypto/hmac_prng.c"
							"src/crypto/hmac.c"
							"src/crypto/sha256.c"
							"src/crypto/sha512.c"
							"src/crypto/utils.c"
							"src/crypto/group_element.c"
							"src/crypto/field_element.c"
							"src/crypto/ed_dsa.c"
							"src/crypto/sc.c"
							"src/psa/cipher_wrap.c"
							"src/psa/psa_crypto_aead.c"
							"src/psa/psa_crypto_cipher.c"
							"src/psa/psa_crypto_client.c"
							"src/psa/psa_crypto_driver_wrappers.c"
							"src/psa/psa_crypto_ecp.c"
							"src/psa/psa_crypto_hash.c"
							"src/psa/psa_crypto_rsa.c"
							"src/psa/psa_crypto_porting.c"
							"src/psa/psa_crypto_slot_management.c"
							"src/psa/psa_crypto.c"
							"src/psa/psa_crypto_storage.c"
							"src/psa/psa_its_file.c"
							"src/psa/psa_its_flash.c"
							"src/psa/psa_its_nvs.c"
							"src/utils/iotex_dev_access.c"
							"src/utils/cJSON/cJSON.c"
							"src/utils/keccak256/keccak256.c"
							"src/utils/ProtoBuf/devnet_upload.pb.c"
							"src/utils/ProtoBuf/header.pb.c"
							"src/utils/ProtoBuf/payload.pb.c"
							"src/utils/ProtoBuf/packconfirm.pb.c"
							"src/utils/ProtoBuf/pb_common.c"
							"src/utils/ProtoBuf/pb_decode.c"
							"src/utils/ProtoBuf/pb_encode.c"
							"src/utils/baseX/base64.c"
							"src/utils/baseX/base58.c"
							"src/utils/LowerS/LowerS.c"
							"src/hal/flash/flash_common.c"
							"src/hal/flash/soc/esp32/flash.c"
							"src/hal/nvs/nvs_common.c"
							"src/hal/nvs/soc/esp32/nvs_esp32.c"
							"src/dids/did/did.c"
							"src/dids/did/did_key.c"
							"src/dids/did/did_io.c"
							"src/jose/jwk.c"
							"src/jose/jws.c"
							"src/jose/jwe.c"
							"src/jose/jwt.c"
							"src/dids/didcomm/message.c"
							"src/dids/didcomm/from_prior.c"
							"src/dids/vc/vc.c"
                    INCLUDE_DIRS "." 
							"src" 
							"${ESP_IDF_PATH}/components/nvs_flash/include" 
							"${ESP_IDF_PATH}/components/esp_partition/include")

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

target_include_directories(DeviceConnectCore 
    PUBLIC src
)

file(GLOB_RECURSE sources CONFIGURE_DEPENDS src/*.c src/*.h)

target_sources(DeviceConnectCore 
  PRIVATE
    src/DeviceConnect_Core.c
	src/crypto/aes_decrypt.c
	src/crypto/aes_encrypt.c
	src/crypto/cbc_mode.c
	src/crypto/ccm_mode.c
	src/crypto/cmac_mode.c
	src/crypto/ctr_mode.c
	src/crypto/ctr_prng.c
	src/crypto/ecc_dh.c
	src/crypto/ecc_dsa.c
	src/crypto/ecc_platform_specific.c
	src/crypto/ecc.c
	src/crypto/hmac_prng.c
	src/crypto/hmac.c
	src/crypto/sha256.c
	src/crypto/utils.c
	src/psa/cipher_wrap.c
	src/psa/psa_crypto_cipher.c
	src/psa/psa_crypto_client.c
	src/psa/psa_crypto_driver_wrappers.c
	src/psa/psa_crypto_ecp.c
	src/psa/psa_crypto_hash.c
	src/psa/psa_crypto_rsa.c
	src/psa/psa_crypto_porting.c
	src/psa/psa_crypto_slot_management.c
	src/psa/psa_crypto.c
	src/psa/psa_crypto_storage.c
	src/psa/psa_its_file.c
	src/psa/psa_its_flash.c
	src/utils/iotex_dev_access.c
	src/utils/cJSON/cJSON.c
	src/utils/keccak256/keccak256.c
	src/utils/ProtoBuf/devnet_upload.pb.c
	src/utils/ProtoBuf/header.pb.c
	src/utils/ProtoBuf/payload.pb.c
	src/utils/ProtoBuf/packconfirm.pb.c
	src/utils/ProtoBuf/pb_common.c
	src/utils/ProtoBuf/pb_decode.c
	src/utils/ProtoBuf/pb_encode.c
	src/utils/base64/base64.c
	src/utils/LowerS/LowerS.c
	src/hal/flash/flash_common.c
	src/hal/nvs/nvs_common.c
)



