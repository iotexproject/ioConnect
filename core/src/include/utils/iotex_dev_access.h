#ifndef __IOTEX_DEV_ACCESS_H__
#define __IOTEX_DEV_ACCESS_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "include/utils/cJSON/cJSON.h"
#include "include/utils/baseX/base64.h"
#include "include/utils/keccak256/keccak256.h"
#include "include/utils/ProtoBuf/pb_common.h"
#include "include/utils/ProtoBuf/pb_decode.h"
#include "include/utils/ProtoBuf/pb_encode.h"
#include "include/utils/ProtoBuf/devnet_upload.pb.h"


#define IOTEX_KEEP_ALIVE                        60
#define IOTEX_MAX_TOPIC_NUM                     1
#define IOTEX_MAX_TOPIC_SIZE                    64
#define IOTEX_MQTT_QOS                          0
#define IOTEX_MAX_TOKEN_SIZE					160

#define IOTEX_DEV_ACCESS_ERR_SUCCESS                0x00
#define IOTEX_DEV_ACCESS_ERR_NO_INIT               	-0x01
#define IOTEX_DEV_ACCESS_ERR_GENERAL               	-0x02
#define IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER   	-0x03
#define IOTEX_DEV_ACCESS_ERR_BAD_STATUS				-0x04
#define IOTEX_DEV_ACCESS_ERR_ALLOCATE_FAIL			-0x05
#define IOTEX_DEV_ACCESS_ERR_SEND_DATA_FAIL			-0x06
#define IOTEX_DEV_ACCESS_ERR_LINK_NOT_ESTABLISH		-0x07

#define IOTEX_DEV_ACCESS_ERR_TIME_FUNC_EMPTY       	-0x100
#define IOTEX_DEV_ACCESS_ERR_SIGN_FUNC_EMPTY       	-0x101
#define IOTEX_DEV_ACCESS_ERR_MQTT_PUB_FUNC_EMPTY   	-0x102
#define IOTEX_DEV_ACCESS_ERR_MQTT_SUB_FUNC_EMPTY   	-0x103

#define IOTEX_DEV_ACCESS_ERR_JSON_FAIL				-0x200

#define IOTEX_DEVICE_ID_LEN                     15

#define DATA_BUFFER_SIZE                        500

#define IOTEX_WALLET_SIZE                       160
#define IOTEX_DEVICE_ID_SIZE                    16
#define IOTEX_SIGN_VALUE_SIZE                   68

#define IOTEX_DEV_REG_DEBUG_ENABLE              1
#define IOTEX_DEV_REG_DEBUG_DISABLE             0

#define DEFAULT_CHANNEL  8183
#define DEFAULT_UPLOAD_PERIOD   300

#define IOTEX_DATA_CHANNEL_IS_SET(x, c)   (((x) & (c)) == (c))

#define IOTEX_PUB_ID_DEFAULT			"ESP32"
#define IOTEX_EVENT_ID_DEFAULT			"ESP32"

#define IOTEX_MQTT_SUB_TOPIC_DEFAULT	IOTEX_MQTT_TOPIC_DEFAULT "/" IOTEX_PUB_ID_DEFAULT

#define IOTEX_WEBSTREAM_STUDIO_COMMUNICATE_TYPE		"mqtt"
#define IOTEX_WEBSTREAM_STUDIO_URL					"devnet-staging-mqtt.w3bstream.com"
#define IOTEX_WEBSTREAM_STUDIO_PORT					"1883"
#define IOTEX_WEBSTREAM_STUDIO_ADDRESS				IOTEX_WEBSTREAM_STUDIO_COMMUNICATE_TYPE "://" IOTEX_WEBSTREAM_STUDIO_URL ":" IOTEX_WEBSTREAM_STUDIO_PORT

#define IOTEX_EVENT_TYPE_PUBKEY 		"PUBKEY"
#define IOTEX_EVENT_TYPE_DEFAULT 		"DEFAULT"

#define IOTEX_PUB_TIME_TEST_DEFAULT		1683868814000

enum MQTT_PUB_TOPIC{
    IOTEX_MQTT_QUERY_STATUS,
    IOTEX_MQTT_PROPOSER,
    IOTEX_MQTT_PUB_TOPICS
};

enum UserData_Type {
    IOTEX_USER_DATA_TYPE_JSON = 0,
	IOTEX_USER_DATA_TYPE_PB,
	IOTEX_USER_DATA_TYPE_RAW
};

typedef time_t (*iotex_gettime)(void);
typedef int (*iotex_mqtt_pub)(unsigned char *topic, unsigned char *buf, unsigned int buflen, int qos);
typedef int (*iotex_mqtt_sub)(unsigned char *topic);

typedef int (*iotex_sign_message)(const uint8_t * input, size_t input_length, uint8_t * signature, size_t * signature_length );

#ifdef IOTEX_DEBUG_ENABLE
typedef int (*iotex_verify_message)(const uint8_t * input, size_t input_length, const uint8_t * signature, size_t signature_length );
#endif   

enum IOTEX_MQTT_STATUS {
	IOTEX_MQTT_DISCONNECTED,
	IOTEX_MQTT_CONNECTED,
    IOTEX_MQTT_BIND_STATUS_OK,
};

typedef struct iotex_mqtt_ctx {

	enum IOTEX_MQTT_STATUS	status;
	char topic[IOTEX_MAX_TOPIC_NUM][IOTEX_MAX_TOPIC_SIZE];
	char token[IOTEX_MAX_TOKEN_SIZE];

    iotex_mqtt_pub mqtt_pub_func;
    iotex_mqtt_sub mqtt_sub_func;

}iotex_mqtt_ctx_t;

typedef struct iotex_crypto_ctx {

    unsigned char wallet_addr[IOTEX_WALLET_SIZE];
    unsigned char sign_value[IOTEX_SIGN_VALUE_SIZE];

    iotex_sign_message sign_func;
#ifdef IOTEX_DEBUG_ENABLE
    iotex_verify_message verify_func;
#endif

}iotex_crypto_ctx_t;

typedef struct iotex_dev_ctx {

    int  inited;
    int  status;
    int  debug_enable;

    iotex_gettime get_time_func;

    iotex_mqtt_ctx_t mqtt_ctx;
    iotex_crypto_ctx_t crypto_ctx;

}iotex_dev_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

int  iotex_dev_access_init(void);
void iotex_dev_access_loop(void);

void iotex_devreg_debug_enable(int enable);

int iotex_dev_access_set_token(const char *token, int token_len);
int iotex_dev_access_set_mqtt_topic(const char *topic, int topic_len, int topic_location);
int iotex_dev_access_set_time_func(iotex_gettime get_time_func);
int iotex_dev_access_set_mqtt_func(iotex_mqtt_pub mqtt_pub, iotex_mqtt_sub mqtt_sub);
int iotex_dev_access_set_sign_func(iotex_sign_message sign_func);
#ifdef IOTEX_DEBUG_ENABLE
int iotex_dev_access_set_verify_func(iotex_verify_message verify_func);
#endif
int iotex_dev_access_set_mqtt_status(enum IOTEX_MQTT_STATUS status);

int iotex_dev_access_mqtt_input(uint8_t *topic, uint8_t *payload, uint32_t len);
int iotex_dev_access_generate_dev_addr(const unsigned char* public_key, char *dev_address);

int iotex_dev_access_data_upload_with_userdata(void *buf, size_t buf_len, enum UserData_Type type, int8_t mac[6]);
char *iotex_dev_access_get_mqtt_connect_addr_in_format(void);
char *iotex_dev_access_get_mqtt_connect_addr_in_url(void);
int iotex_dev_access_get_mqtt_connect_port(void);

int iotex_dev_access_query_dev_register_status(int8_t mac[6]);
int iotex_dev_access_dev_register_confirm(int8_t mac[6]);

int iotex_user_wallet_addr_set(char *buf, int32_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* __IOTEX_DEV_ACCESS_H__ */
