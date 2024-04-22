#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "include/common.h"
#include "include/utils/iotex_dev_access.h"
#include "include/server/crypto.h"

#ifdef CONFIG_PSA_ITS_FLASH_C
#include "include/hal/flash/flash_common.h"
#endif

#ifdef CONFIG_PSA_ITS_NVS_C
#include "include/hal/nvs/nvs_common.h"
#endif

#include "DeviceConnect_Core.h"

#define USER_WALLET_ADDR_LEN_MAX 			200
#define DEFAULT_TIME_STAMP_UNIX_VALUE      	1701284562

extern psa_key_id_t g_sdkcore_key;

iotex_dev_ctx_t *dev_ctx = NULL;

static char wallet_addr[USER_WALLET_ADDR_LEN_MAX] = {0};

static char str2Hex(char c) {

    if (c >= '0' && c <= '9') {
        return (c - '0');
    }

    if (c >= 'a' && c <= 'z') {
        return (c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'Z') {
        return (c -'A' + 10);
    }

    return c;
}

static int hexStr2Bin(char *str, char *bin) {
	
    int i,j;
    for(i = 0,j = 0; j < (strlen(str)>>1) ; i++,j++) {
        bin[j] = (str2Hex(str[i]) <<4);
        i++;
        bin[j] |= str2Hex(str[i]);
    }

    return j; 
}

int iotex_user_wallet_addr_set(char *buf, int32_t buf_len) {

    if (NULL == buf) {
        return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;
	}

	if (0 == buf_len || buf_len > USER_WALLET_ADDR_LEN_MAX)
		return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;

    memcpy(wallet_addr, buf, buf_len);

    return 0;

}

int iotex_dev_access_init(void)
{
	if (NULL == dev_ctx)
		dev_ctx = (iotex_dev_ctx_t *)malloc(sizeof(iotex_dev_ctx_t));

	if (NULL == dev_ctx)
		return IOTEX_DEV_ACCESS_ERR_ALLOCATE_FAIL;

	memset(dev_ctx, 0, sizeof(iotex_dev_ctx_t));
	memcpy(dev_ctx->mqtt_ctx.topic[0], CONFIG_APP_DEVNET_ACCESS_STUDIO_TOPIC, strlen(CONFIG_APP_DEVNET_ACCESS_STUDIO_TOPIC));
	memcpy(dev_ctx->mqtt_ctx.token, CONFIG_APP_DEVNET_ACCESS_STUDIO_TOKEN, strlen(CONFIG_APP_DEVNET_ACCESS_STUDIO_TOKEN));   

#ifdef CONFIG_PSA_ITS_FLASH_C
	iotex_hal_flash_drv_init();
#endif

#ifdef CONFIG_PSA_ITS_NVS_C
	iotex_hal_nvs_drv_init();
#endif

	dev_ctx->inited = 1;

    return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_set_mqtt_topic(const char *topic, int topic_len, int topic_location) {
    if( (NULL == dev_ctx) || (0 == dev_ctx->inited) )
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

    if( NULL == topic )
        return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;

    if( (topic_location >= IOTEX_MAX_TOPIC_NUM) || (topic_len > IOTEX_MAX_TOPIC_SIZE) )
        return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;

    memset(dev_ctx->mqtt_ctx.topic[topic_location], 0, IOTEX_MAX_TOPIC_SIZE);
    memcpy(dev_ctx->mqtt_ctx.topic[topic_location], topic, strlen(topic));

#ifdef IOTEX_DEBUG_ENABLE
    if( dev_ctx->debug_enable ) {
        printf("Success to set mqtt topic: \n");
        printf("topic : %s\n", dev_ctx->mqtt_ctx.topic[topic_location]);
    }
#endif
    return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_set_token(const char *token, int token_len) {
    if( (NULL == dev_ctx) || (0 == dev_ctx->inited) )
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

    if( (NULL == token) || (token_len > IOTEX_MAX_TOKEN_SIZE) )
        return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;

    memset(dev_ctx->mqtt_ctx.token, 0, IOTEX_MAX_TOKEN_SIZE);
    memcpy(dev_ctx->mqtt_ctx.token, token, strlen(token));

#ifdef IOTEX_DEBUG_ENABLE
    if( dev_ctx->debug_enable ) {
        printf("Success to set token: \n");
        printf("token : %s\n", dev_ctx->mqtt_ctx.token);
    }
#endif
    return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_set_time_func(iotex_gettime get_time_func) {

    if( (NULL == dev_ctx) || (0 == dev_ctx->inited) ) {
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;
    }

 	dev_ctx->get_time_func = get_time_func;

   	return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_set_mqtt_func(iotex_mqtt_pub mqtt_pub, iotex_mqtt_sub mqtt_sub) {

    if( (NULL == dev_ctx) || (0 == dev_ctx->inited) ) {
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;
    }

    dev_ctx->mqtt_ctx.mqtt_pub_func = mqtt_pub;
    dev_ctx->mqtt_ctx.mqtt_sub_func = mqtt_sub;

    return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_set_sign_func(iotex_sign_message sign_func) {

    if( (NULL == dev_ctx) || (0 == dev_ctx->inited) ) {
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;
    }

    dev_ctx->crypto_ctx.sign_func = sign_func;

    return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

#ifdef IOTEX_DEBUG_ENABLE
int iotex_dev_access_set_verify_func(iotex_verify_message verify_func) {

    if( (NULL == dev_ctx) || (0 == dev_ctx->inited) ) {
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;
    }

    dev_ctx->crypto_ctx.verify_func = verify_func;

    return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}
#endif

static int iotex_dev_access_send_data(unsigned char *buf, unsigned int buflen) {

    int ret = 0;

    if( NULL == dev_ctx || 0 == dev_ctx->inited )
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

    if( (NULL == buf) || (0 == buflen))
        return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;

#ifndef ARDUINO 
    if( NULL == dev_ctx->mqtt_ctx.mqtt_pub_func )
        return IOTEX_DEV_ACCESS_ERR_MQTT_PUB_FUNC_EMPTY;
#endif
	
#ifdef ARDUINO
extern int iotex_device_connect_mqtt_pub(unsigned char *topic, unsigned char *buf, unsigned int buflen, int qos);
	ret = iotex_device_connect_mqtt_pub((unsigned char *)dev_ctx->mqtt_ctx.topic[0], buf, buflen, 0);
#else
    ret = dev_ctx->mqtt_ctx.mqtt_pub_func((unsigned char *)dev_ctx->mqtt_ctx.topic[0], buf, buflen, 0);
#endif

#ifdef IOTEX_DEBUG_ENABLE
    if( dev_ctx->debug_enable ) {
        printf("Sending  [%s]: %d\n", dev_ctx->mqtt_ctx.topic[0], ret);
    }
#endif

    return (ret ? IOTEX_DEV_ACCESS_ERR_SUCCESS : IOTEX_DEV_ACCESS_ERR_SEND_DATA_FAIL);
}

int iotex_dev_access_mqtt_input(uint8_t *topic, uint8_t *payload, uint32_t len) {
    if( NULL == dev_ctx || 0 == dev_ctx->inited )
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

    if( topic == NULL || payload == NULL || len == 0)
        return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;

    return IOTEX_DEV_ACCESS_ERR_SUCCESS;

}

void iotex_dev_access_loop(void) {

	// TODO: Loop code here
}

int iotex_dev_access_data_upload_with_userdata(void *buf, size_t buf_len, enum UserData_Type type, int8_t mac[6]) {

	char sign_buf[64]  = {0};
	unsigned int  sign_len = 0;
	char *message = NULL;
	size_t message_len = 0;

	if (NULL == dev_ctx || 0 == dev_ctx->inited)
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

	if (dev_ctx->mqtt_ctx.status != IOTEX_MQTT_BIND_STATUS_OK)
		return IOTEX_DEV_ACCESS_ERR_BAD_STATUS;

	unsigned char *buffer = malloc(Upload_size);
	if (NULL == buffer)
		return IOTEX_DEV_ACCESS_ERR_ALLOCATE_FAIL;

	if (NULL == buf || 0 == buf_len)
		return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;

	pb_ostream_t ostream_upload = {0};
	Upload upload = Upload_init_default;

	upload.has_header = true;
	strcpy(upload.header.event_id, IOTEX_EVENT_ID_DEFAULT);
	strcpy(upload.header.pub_id,   IOTEX_PUB_ID_DEFAULT);
	strcpy(upload.header.event_type, IOTEX_EVENT_TYPE_DEFAULT);
	strcpy(upload.header.token, dev_ctx->mqtt_ctx.token);
	upload.header.pub_time = IOTEX_PUB_TIME_TEST_DEFAULT;

	upload.payload.ptype = Payload_PackageType_USERDATA;
 	upload.payload.dtype = type;

 	switch (type) {

 		case IOTEX_USER_DATA_TYPE_JSON:

 			message = cJSON_PrintUnformatted((const cJSON *)buf);
 			message_len = strlen(message);

 			upload.payload.user.size = message_len;
 			memcpy(upload.payload.user.bytes, message, message_len);

 			break;
 		case IOTEX_USER_DATA_TYPE_PB:

 			upload.payload.user.size = buf_len;
 			memcpy(upload.payload.user.bytes, buf, buf_len);

 			message = (char *)buf;
 			message_len = buf_len;

 			break;
 		case IOTEX_USER_DATA_TYPE_RAW:

 			upload.payload.user.size = buf_len;
			memcpy(upload.payload.user.bytes, buf, buf_len);

 			message = (char *)buf;
 			message_len = buf_len;

 			break;
 		default:
 			return IOTEX_DEV_ACCESS_ERR_BAD_INPUT_PARAMETER;
 	}

 	psa_sign_message( g_sdkcore_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), (const uint8_t *)message, message_len, (uint8_t *)sign_buf, 64, (size_t *)&sign_len);

 	upload.has_payload = true;
 	upload.payload.sign.size = sign_len;
 	memcpy(upload.payload.sign.bytes, sign_buf, sign_len);

	upload.payload.pubkey.size = 65;
    memcpy(upload.payload.pubkey.bytes, iotex_deviceconnect_sdk_core_get_public_key(), 65);

	upload.payload.mac.size = 6;
	memcpy(upload.payload.mac.bytes, mac, 6);

	upload.payload.has_pConfirm = false;

	memset(buffer, 0, Upload_size);
	ostream_upload  = pb_ostream_from_buffer(buffer, Upload_size);
	if (!pb_encode(&ostream_upload, Upload_fields, &upload)) {
		printf("pb encode [event] error in [%s]\n", PB_GET_ERROR(&ostream_upload));
		goto exit;
	}

#ifdef IOTEX_DEBUG_ENABLE
	printf("Event Upload len %d\n", ostream_upload.bytes_written);

	for (int i = 0; i < ostream_upload.bytes_written; i++) {
		printf("%02x ", buffer[i]);
	}
	printf("\n");
#endif

	iotex_dev_access_send_data(buffer, ostream_upload.bytes_written);

exit:
	if(buffer) {
		free(buffer);
		buffer = NULL;
	}

	if (IOTEX_USER_DATA_TYPE_JSON == type &&  message) {
		free(message);
		message = NULL;
	}

	return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_query_dev_register_status(int8_t mac[6]) {

	if (NULL == dev_ctx || 0 == dev_ctx->inited)
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

	if (dev_ctx->mqtt_ctx.status != IOTEX_MQTT_CONNECTED)
		return IOTEX_DEV_ACCESS_ERR_BAD_STATUS;

	unsigned char *buffer = malloc(Upload_size);
	if (NULL == buffer)
		return IOTEX_DEV_ACCESS_ERR_ALLOCATE_FAIL;

	pb_ostream_t ostream_upload = {0};
	Upload upload = Upload_init_default;

	upload.has_header = true;
	strcpy(upload.header.event_id, IOTEX_EVENT_ID_DEFAULT);
	strcpy(upload.header.pub_id,   IOTEX_PUB_ID_DEFAULT);
	strcpy(upload.header.event_type, IOTEX_EVENT_TYPE_DEFAULT);
	strcpy(upload.header.token, dev_ctx->mqtt_ctx.token);
	upload.header.pub_time = IOTEX_PUB_TIME_TEST_DEFAULT;

 	upload.has_payload = true;
 	upload.payload.ptype = Payload_PackageType_QUERY;

	upload.payload.mac.size = 6;
	memcpy(upload.payload.mac.bytes, mac, 6);

	memset(buffer, 0, Upload_size);
	ostream_upload  = pb_ostream_from_buffer(buffer, Upload_size);
	if (!pb_encode(&ostream_upload, Upload_fields, &upload)) {
		printf("pb encode [event] error in [%s]\n", PB_GET_ERROR(&ostream_upload));
		goto exit;
	}

#ifdef IOTEX_DEBUG_ENABLE
	printf("Event Upload len %d\n", ostream_upload.bytes_written);

	for (int i = 0; i < ostream_upload.bytes_written; i++) {
		printf("%02x ", buffer[i]);
	}
	printf("\n");
#endif

	iotex_dev_access_send_data(buffer, ostream_upload.bytes_written);

exit:
	if(buffer) {
		free(buffer);
		buffer = NULL;
	}

	return IOTEX_DEV_ACCESS_ERR_SUCCESS;	
}

int iotex_dev_access_dev_register_confirm(int8_t mac[6]) {

	char raw_data[24]  = {0};
	char sign_buf[64]  = {0};
	unsigned int  sign_len = 0;

	if (NULL == dev_ctx || 0 == dev_ctx->inited)
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

	if (dev_ctx->mqtt_ctx.status != IOTEX_MQTT_CONNECTED)
		return IOTEX_DEV_ACCESS_ERR_BAD_STATUS;

	unsigned char *buffer = malloc(Upload_size);
	if (NULL == buffer)
		return IOTEX_DEV_ACCESS_ERR_ALLOCATE_FAIL;

	uint32_t timestamp = time(0);
	if (timestamp < DEFAULT_TIME_STAMP_UNIX_VALUE)
		timestamp = DEFAULT_TIME_STAMP_UNIX_VALUE;
	
	pb_ostream_t ostream_upload = {0};
	Upload upload = Upload_init_default;

	upload.has_header = true;
	strcpy(upload.header.event_id, IOTEX_EVENT_ID_DEFAULT);
	strcpy(upload.header.pub_id,   IOTEX_PUB_ID_DEFAULT);
	strcpy(upload.header.event_type, IOTEX_EVENT_TYPE_DEFAULT);
	strcpy(upload.header.token, dev_ctx->mqtt_ctx.token);
	upload.header.pub_time = IOTEX_PUB_TIME_TEST_DEFAULT;

 	upload.has_payload = true;
 	upload.payload.ptype = Payload_PackageType_COMFIRM;

	upload.payload.mac.size = 6;
	memcpy(upload.payload.mac.bytes, mac, 6);

	upload.payload.pubkey.size = 65;
    memcpy(upload.payload.pubkey.bytes, iotex_deviceconnect_sdk_core_get_public_key(), 65);	

	upload.payload.has_pConfirm = true;

	upload.payload.pConfirm.owner.size = hexStr2Bin(wallet_addr + 2, (char *)upload.payload.pConfirm.owner.bytes);
	
	memcpy(raw_data, upload.payload.pConfirm.owner.bytes, upload.payload.pConfirm.owner.size);
	raw_data[upload.payload.pConfirm.owner.size]     = (char)((timestamp & 0xFF000000) >> 24);
    raw_data[upload.payload.pConfirm.owner.size + 1] = (char)((timestamp & 0x00FF0000) >> 16);
    raw_data[upload.payload.pConfirm.owner.size + 2] = (char)((timestamp & 0x0000FF00) >> 8);
    raw_data[upload.payload.pConfirm.owner.size + 3] = (char)(timestamp & 0x000000FF);	

	psa_sign_message( g_sdkcore_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), (const uint8_t *)(raw_data), upload.payload.pConfirm.owner.size + 4, (uint8_t *)sign_buf, 64, (size_t *)&sign_len);
	LowsCalc(sign_buf + 32, sign_buf + 32);
	
	upload.payload.pConfirm.timestamp = timestamp;

	upload.payload.pConfirm.signature.size = sign_len;
	memcpy(upload.payload.pConfirm.signature.bytes, sign_buf, sign_len);

	upload.payload.pConfirm.channel = 8183;
	
	memset(buffer, 0, Upload_size);
	ostream_upload  = pb_ostream_from_buffer(buffer, Upload_size);
	if (!pb_encode(&ostream_upload, Upload_fields, &upload)) {
		printf("pb encode [event] error in [%s]\n", PB_GET_ERROR(&ostream_upload));
		goto exit;
	}

#ifdef IOTEX_DEBUG_ENABLE
	printf("Event Upload len %d\n", ostream_upload.bytes_written);
	for (int i = 0; i < ostream_upload.bytes_written; i++) {
		printf("%02x ", buffer[i]);
	}
	printf("\n");
#endif

	iotex_dev_access_send_data(buffer, ostream_upload.bytes_written);

exit:
	if(buffer) {
		free(buffer);
		buffer = NULL;
	}

	return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_set_mqtt_status(enum IOTEX_MQTT_STATUS status) {

	if( NULL == dev_ctx || 0 == dev_ctx->inited ) {
		return IOTEX_DEV_ACCESS_ERR_NO_INIT;
	}

	dev_ctx->mqtt_ctx.status = status;
#ifdef IOTEX_DEBUG_ENABLE
#ifndef IOTEX_DEBUG_ENABLE_FORCE
	if( dev_ctx->debug_enable ) {
#endif
		printf("mqtt status set %d\n", dev_ctx->mqtt_ctx.status);
#ifndef IOTEX_DEBUG_ENABLE_FORCE
	}
#endif
#endif

	return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_debug_enable(int enable) {

    if( NULL == dev_ctx || 0 == dev_ctx->inited )
        return IOTEX_DEV_ACCESS_ERR_NO_INIT;

    dev_ctx->debug_enable = enable;

    return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

int iotex_dev_access_generate_dev_addr(const unsigned char* public_key, char *dev_address)
{
	// The device address is the hex string representation of the last 20 bytes of the keccak256 hash of the public key.

	uint8_t hash[32] = {0};
	keccak256_getHash(public_key + 1, 64, hash);

    dev_address[0] = '0';
    dev_address[1] = 'x';

	for (int i=0; i<20; i++)
	{
		char buf[3] = {0};
		sprintf(buf, "%02x", hash[32 - 20 + i]);

        memcpy(dev_address + 2 + i * 2, buf, 2);

	}

	return IOTEX_DEV_ACCESS_ERR_SUCCESS;
}

char *iotex_dev_access_get_mqtt_connect_addr_in_url(void) {

#ifdef IOTEX_WEBSTREAM_STUDIO_URL
	return IOTEX_WEBSTREAM_STUDIO_URL;
#else
	return NULL;
#endif

}

char *iotex_dev_access_get_mqtt_connect_addr_in_format(void) {

#ifdef IOTEX_WEBSTREAM_STUDIO_ADDRESS
	return IOTEX_WEBSTREAM_STUDIO_ADDRESS;
#else
	return NULL;
#endif

}

int iotex_dev_access_get_mqtt_connect_port(void) {

#ifdef IOTEX_WEBSTREAM_STUDIO_PORT
	return atoi(IOTEX_WEBSTREAM_STUDIO_PORT);
#else
	return 0;
#endif

}


