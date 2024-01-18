#include "DeviceConnect_Core.h"

#define SPROUT_HTTP_DATA_TYPE_SEND          1
#define SPROUT_HTTP_DATA_TYPE_JWT           2

#define SPROUT_MESSAGE_ID_SIZE              256
#define SPROUT_QUERY_PATH_SIZE              128
#define SPROUT_DID_TOKEN_SIZE               1024
#define SPROUT_HTTP_REPLY_BUF_SIZE          10240

#define IOTEX_SPROUT_ERR_SUCCESS            0
#define IOTEX_SPROUT_ERR_BAD_INPUT_PARA     -1
#define IOTEX_SPROUT_ERR_DATA_FORMAT        -2

char *iotex_sprout_project_query_path_get(void);
char *iotex_sprout_http_send_message(char *post_field, int post_field_len);
int iotex_device_connect_pal_sprout_http_query(char *message_id, int message_id_len);
