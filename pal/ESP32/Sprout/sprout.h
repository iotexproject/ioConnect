#include "DeviceConnect_Core.h"

#define SPROUT_HTTP_RESPONSE_DATA_TYPE_SEND          1
#define SPROUT_HTTP_RESPONSE_DATA_TYPE_JWT           2
#define SPROUT_HTTP_RESPONSE_DATA_TYPE_DIDDOC        3
#define SPROUT_HTTP_RESPONSE_DATA_TYPE_QUERY         4

#define SPROUT_MESSAGE_ID_SIZE              256
#define SPROUT_QUERY_PATH_SIZE              128
#define SPROUT_DID_TOKEN_SIZE               1024
#define SPROUT_HTTP_REPLY_BUF_SIZE          1024 * 8

#define IOTEX_SPROUT_ERR_SUCCESS                0
#define IOTEX_SPROUT_ERR_BAD_INPUT_PARA         -1
#define IOTEX_SPROUT_ERR_DATA_FORMAT            -2
#define IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY    -3

DIDDoc *iotex_pal_sprout_server_diddoc_get(void);
int iotex_pal_sprout_request_token(char *did, char *ka_kid);
int iotex_pal_sprout_msg_query(char *ka_kid);
char *iotex_pal_sprout_send_message(char *message, char *ka_kid);
