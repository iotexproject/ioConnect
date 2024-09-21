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
							"src/utils/devRegister/devRegister.c"
							"src/utils/convert/convert.c"
							"src/hal/flash/flash_common.c"
							"src/hal/flash/soc/esp32/flash.c"
							"src/hal/nvs/nvs_common.c"
							"src/hal/nvs/soc/esp32/nvs_esp32.c"
							"src/dids/did/did.c"
							"src/dids/did/did_key.c"
							"src/dids/did/did_io.c"
							"src/dids/did/registry.c"
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

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if  (NOT DEFINED COMPILE_LIB_SET)
	option (COMPILE_LIB_SET "Set ioConnectCore compile to a Lib" OFF)
endif()


project(ioConnectcCore)

include_directories(src)

file (GLOB_RECURSE SRC_LIST ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/src)

if (COMPILE_LIB_SET)
	add_library (ioConnectCore SHARED ${SRC_LIST})	
else()
	set (ioConnectCore_SRC ${SRC_LIST} PARENT_SCOPE)
endif()




