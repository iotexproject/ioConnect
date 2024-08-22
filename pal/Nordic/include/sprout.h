#ifndef __IOCONNECT_PAL_SPROUT_H__
#define __IOCONNECT_PAL_SPROUT_H__

#define SPROUT_COMMUNICATE_TYPE_NORMAL      1
#define SPROUT_COMMUNICATE_TYPE_DID         2

#define IOTEX_SPROUT_COMMUNICATE_TYPE       SPROUT_COMMUNICATE_TYPE_DID

#define IOTEX_SPROUT_HTTP_URL                   "/didDoc"
#define IOTEX_SPROUT_HTTP_HOST                  "sprout-testnet.w3bstream.com"
#define IOTEX_SPROUT_HTTP_IP                    "35.193.59.58"
#define IOTEX_SPROUT_HTTP_PORT_STRING           "80"         // "9000"
#define IOTEX_SPROUT_HTTP_PORT_DEMICAL          80
#define IOTEX_SPROUT_HTTPS_PORT_STRING         "443"
#define IOTEX_SPROUT_HTTPS_PORT_DEMICAL         443

#define IOTEX_SPROUT_HTTP_TIMEOUT               5000

#define IOTEX_SPROUT_HTTP_PATH_MESSAGE          "/message"
#define IOTEX_SPROUT_HTTP_PATH_REQUEST_TOKEN    "/issue_vc"
#define IOTEX_SPROUT_HTTP_PATH_GET_DIDDOC       "/didDoc"

#define IOTEX_SPROUT_HTTP_HEADER_HEAD           "Authorization: Bearer "
#define IOTEX_SPROUT_HTTP_HEADER_END            "\r\n"
#define IOTEX_SPROUT_HTTP_MESSAGE_QUERY_PATH_HEAD           "/message/"

#define REQUEST "GET /didDoc HTTP/1.1\r\nHost: sprout-testnet.w3bstream.com\r\nConnection: close\r\n\r\n"

#define SPROUT_HTTP_RESPONSE_DATA_TYPE_SEND          1
#define SPROUT_HTTP_RESPONSE_DATA_TYPE_JWT           2
#define SPROUT_HTTP_RESPONSE_DATA_TYPE_DIDDOC        3
#define SPROUT_HTTP_RESPONSE_DATA_TYPE_QUERY         4

#define SPROUT_QUERY_PATH_SIZE              128
#define SPROUT_DID_TOKEN_SIZE               1024

#define IOTEX_PAL_SPROUT_SERVER_KA_KID_MAX_SIZE     128
#define IOTEX_PAL_SPROUT_QUERY_PATH_MAX_SIZE        128
#define IOTEX_PAL_SPROUT_MESSAGE_ID_MAX_SIZE        256
#define IOTEX_PAL_SPROUT_HTTP_REPLY_BUF_MAX_SIZE    256     // 1024 * 8
#define IOTEX_PAL_SPROUT_HTTP_HEADER_MAX_SIZE       1024

#define IOTEX_SPROUT_ERR_SUCCESS                0
#define IOTEX_SPROUT_ERR_BAD_INPUT_PARA         -1
#define IOTEX_SPROUT_ERR_DATA_FORMAT            -2
#define IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY    -3
#define IOTEX_SPROUT_ERR_BAD_STATUS             -4
#define IOTEX_SPROUT_ERR_ENCRYPT_FAIL           -5
#define IOTEX_SPROUT_ERR_TIMEOUT                -6

#define IOTEX_PAL_SPROUT_STATUS_INIT                    0
#define IOTEX_PAL_SPROUT_STATUS_SERVER_DIDDOC_GET       1
#define IOTEX_PAL_SPROUT_STATUS_HTTP_TOKEN_GOTTEN       2
#define IOTEX_PAL_SPROUT_STATUS_MESSAGE_ID_GOTTEN       3
#define IOTEX_PAL_SPROUT_STATUS_MESSAGE_QUERY_GOTTEN    4

#define IOTEX_PAL_SPROUT_CTX_TYPE_INIT                  0
#define IOTEX_PAL_SPROUT_CTX_TYPE_SERVER_DIDDOC         1
#define IOTEX_PAL_SPROUT_CTX_TYPE_REQUEST_TOKEN         2
#define IOTEX_PAL_SPROUT_CTX_TYPE_SEND_MESSAGE          3
#define IOTEX_PAL_SPROUT_CTX_TYPE_QUERY_STATUS          4

#define IOTEX_PAL_SPROUT_ERROR_TIMES_MAX                3

int iotex_pal_sprout_init(char *deviceDID, char *deviceKAKID);
int iotex_pal_sprout_loop(void);
int iotex_pal_sprout_http_server_connect(void);
int iotex_pal_sprout_server_request_token(void);
int iotex_pal_sprout_send_message(char *message);
int iotex_pal_sprout_msg_query(char *message_id);

#endif
