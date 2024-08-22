#include <string.h>
#include <stdlib.h>

#include <zephyr/kernel.h>

#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/tls_credentials.h>

#include "include/jose/jose.h"
#include "include/dids/dids.h"

#include "sprout.h"

LOG_MODULE_REGISTER(sprout, CONFIG_ASSET_TRACKER_LOG_LEVEL);

static char _messageID[IOTEX_PAL_SPROUT_MESSAGE_ID_MAX_SIZE]        = {0};
static char _didcommToken[IOTEX_PAL_SPROUT_HTTP_HEADER_MAX_SIZE]    = {0};
static char _replyData[IOTEX_PAL_SPROUT_HTTP_REPLY_BUF_MAX_SIZE]    = {0};
static char _serverKAKID[IOTEX_PAL_SPROUT_SERVER_KA_KID_MAX_SIZE]   = {0};

static struct sockaddr_in _addrServer;
static int    _sock = -1;
static int    _err_times = 0;

static char *_deviceDID = NULL;
static char *_deviceKAKID = NULL;
static char *_client_id_serialize = NULL;

typedef struct _pal_sprout_ctx {

    uint8_t type;
    uint8_t *_replyData;
    uint8_t err_times;

    bool hasFinish;
    struct k_work work;

    struct k_mutex _sprout_mutex;

};

static struct _pal_sprout_ctx _sprout_ctx;

const char *_headers[] = {
    _didcommToken,
    NULL
};

static void _pal_sprout_ctx_deinit(void)
{
    if (_sprout_ctx._replyData) {
        free(_sprout_ctx._replyData);
        _sprout_ctx._replyData = NULL;
    }

    _sprout_ctx.type      = IOTEX_PAL_SPROUT_CTX_TYPE_INIT;
    _sprout_ctx.err_times = 0;
    _sprout_ctx.hasFinish = false;
}

static int _pal_sprout_token_handle(char *cipher_token)
{
    if (NULL == cipher_token)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    if (NULL == _deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    char *token = iotex_jwe_decrypt(cipher_token, Ecdh1puA256kw, A256cbcHs512, NULL, NULL, (char *)_deviceKAKID);
    if (token) {
        memset(_didcommToken + strlen(IOTEX_SPROUT_HTTP_HEADER_HEAD), 0, IOTEX_PAL_SPROUT_HTTP_HEADER_MAX_SIZE - strlen(IOTEX_SPROUT_HTTP_HEADER_HEAD));
        memcpy(_didcommToken + strlen(IOTEX_SPROUT_HTTP_HEADER_HEAD), token, strlen(token));
        memcpy(_didcommToken + strlen(IOTEX_SPROUT_HTTP_HEADER_HEAD) + strlen(token), IOTEX_SPROUT_HTTP_HEADER_END, strlen(IOTEX_SPROUT_HTTP_HEADER_END));

        LOG_INF("Token : %s", _didcommToken + + strlen(IOTEX_SPROUT_HTTP_HEADER_HEAD));

        free(token);

        _err_times = 0;

    } else {
        LOG_ERR("Failed to decrypt token");
        return IOTEX_SPROUT_ERR_ENCRYPT_FAIL;
    }

    return IOTEX_SPROUT_ERR_SUCCESS;
}

static int _pal_sprout_diddoc_handle(char *diddoc)
{
    DIDDoc *diddoc_parse = NULL;

    if (NULL == diddoc)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    diddoc_parse = iotex_diddoc_parse(diddoc);
    if (NULL == diddoc_parse) {

        _sprout_ctx.err_times++;

        LOG_ERR("Failed to Parse the DIDDoc \n");          
        return;
    }

    unsigned int vm_num = iotex_diddoc_verification_method_get_num(diddoc_parse, VM_PURPOSE_KEY_AGREEMENT);
    if (0 == vm_num) {
       
       _sprout_ctx.err_times++;

        LOG_ERR("Not Find Verification Method\n");
        goto diddoc_destroy;
    }

    VerificationMethod_Info *vm_info = iotex_diddoc_verification_method_get(diddoc_parse, VM_PURPOSE_KEY_AGREEMENT, vm_num - 1);             
    if (NULL == vm_info) {
        _err_times++;

        LOG_ERR("Not Find Key Agreement Method in Verification Methods\n");
        goto diddoc_destroy;
    }

    if (vm_info->pubkey_type == VERIFICATION_METHOD_PUBLIC_KEY_TYPE_JWK) {
        iotex_registry_item_register(vm_info->id, vm_info->pk_u.jwk); 
        memset(_serverKAKID, 0, sizeof(_serverKAKID));
        memcpy(_serverKAKID, vm_info->id, strlen(vm_info->id));

        LOG_INF("KA_KID from Server : %s", _serverKAKID);
    } 

diddoc_destroy:
    if (diddoc_parse)
        iotex_diddoc_destroy(diddoc_parse); 

    _err_times = 0;

    return IOTEX_SPROUT_ERR_SUCCESS;
}

static int _pal_sprout_send_messge_handle(char *resp)
{
    if (NULL == resp)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    if (NULL == _deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    char *plaintext = iotex_jwe_decrypt(resp, Ecdh1puA256kw, A256cbcHs512, NULL, NULL, (char *)_deviceKAKID);
    if (NULL == plaintext) {
         LOG_ERR("Failed to Decrypt Message Response");  
         return IOTEX_SPROUT_ERR_ENCRYPT_FAIL;
    }
    
    LOG_INF("Receive Message : %s\n", plaintext);

    cJSON *message_id_root = cJSON_Parse(plaintext);
    if (NULL == message_id_root) {
        
        _err_times++;
        LOG_ERR("Response Message DataFormat Error");
        return IOTEX_SPROUT_ERR_DATA_FORMAT;
    }

    cJSON *message_id_item = cJSON_GetObjectItem(message_id_root, "_messageID");
    if (NULL == message_id_item) {
        
        _err_times++;
        LOG_ERR("Response Message DataFormat Error : No <_messageID> item");
        goto exit;
    }

    memset(_messageID, 0, IOTEX_PAL_SPROUT_MESSAGE_ID_MAX_SIZE);
    memcpy(_messageID, message_id_item->valuestring, strlen(message_id_item->valuestring));

    LOG_INF("Got Message ID : %s", _messageID);

    free(plaintext);

    _err_times = 0;

exit:
    
    cJSON_Delete(message_id_root);  

    return IOTEX_SPROUT_ERR_SUCCESS;
}

static int _pal_sprout_query_handle(char *resp)
{
    if (NULL == resp)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    if (NULL == _deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    char *msg_state = iotex_jwe_decrypt(resp, Ecdh1puA256kw, A256cbcHs512, NULL, NULL, _deviceKAKID);
    if (NULL == msg_state) {
        LOG_ERR("Failed to decrypt message status\n");  
        return IOTEX_SPROUT_ERR_ENCRYPT_FAIL;
    }

    LOG_INF("Receive Message State: %s\n", msg_state);
    
    _err_times = 0;
    
    return IOTEX_SPROUT_ERR_SUCCESS;
}

void _pal_sprout_http_response_parse(struct k_work *item)
{
    if (false == _sprout_ctx.hasFinish)
        return;

    if (NULL == _sprout_ctx._replyData)
        return;

    switch (_sprout_ctx.type) {
        case IOTEX_PAL_SPROUT_CTX_TYPE_SERVER_DIDDOC:

            _pal_sprout_diddoc_handle(_sprout_ctx._replyData);
        
            break;
        case IOTEX_PAL_SPROUT_CTX_TYPE_REQUEST_TOKEN:
            
             _pal_sprout_token_handle(_sprout_ctx._replyData);

            break;
        case IOTEX_PAL_SPROUT_CTX_TYPE_SEND_MESSAGE:
            
            _pal_sprout_send_messge_handle(_sprout_ctx._replyData);

            break;
        case IOTEX_PAL_SPROUT_CTX_TYPE_QUERY_STATUS:

            _pal_sprout_query_handle(_sprout_ctx._replyData);

            break;                                
        default:
            break;
    }

    _pal_sprout_ctx_deinit();

    k_mutex_unlock(&_sprout_ctx._sprout_mutex);

    return;
}

static int _pal_sprout_http_server_connect(void)
{
	char peer_addr[INET_ADDRSTRLEN] = {0};
	
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_socktype = SOCK_STREAM;

    LOG_INF("Looking up %s", IOTEX_SPROUT_HTTP_HOST);
	int err = getaddrinfo(IOTEX_SPROUT_HTTP_HOST, IOTEX_SPROUT_HTTP_PORT_STRING, &hints, &res);
	if (err) {
		LOG_ERR("getaddrinfo() failed, err %d\n", errno);
        err = errno;
        goto exit; 
	}

	inet_ntop(res->ai_family, &((struct sockaddr_in *)(res->ai_addr))->sin_addr, peer_addr, INET_ADDRSTRLEN);
	LOG_INF("Resolved %s (%s) protocol %d\n", peer_addr, net_family2str(res->ai_family), res->ai_protocol);

    _sock = socket(res->ai_family, SOCK_STREAM, res->ai_protocol);
	if (_sock < 0)  {
		LOG_ERR("Failed to create HTTP socket (%d)", -errno);
        err = errno;
        goto exit_1;
    }

	err = connect(_sock, res->ai_addr, res->ai_addrlen);
	if (err) {
		LOG_ERR("connect() failed, err: %d\n", -errno);
        err = errno;
		goto exit_2;
	}

    LOG_INF("Connected to %s:%d\n", IOTEX_SPROUT_HTTP_HOST, ntohs(((struct sockaddr_in *)(res->ai_addr))->sin_port));    

    return 0;
	
exit_2:    
	close(_sock);
    _sock = -1;
exit_1:
    freeaddrinfo(res);
exit:
	return err;    
}

char *payload_str = NULL;
int iotex_pal_sprout_init(char *deviceDID, char *deviceKAKID)
{
    if (NULL == deviceDID || NULL == deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    _deviceDID   = deviceDID;
    _deviceKAKID = deviceKAKID;

    memset(_didcommToken, 0, IOTEX_PAL_SPROUT_HTTP_HEADER_MAX_SIZE);
    memcpy(_didcommToken, IOTEX_SPROUT_HTTP_HEADER_HEAD, strlen(IOTEX_SPROUT_HTTP_HEADER_HEAD));

    _err_times = 0;

    cJSON * client_id = cJSON_CreateObject();
    if (NULL == client_id)
        return IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY;

    cJSON_AddStringToObject(client_id, "clientID", _deviceDID);
    _client_id_serialize = cJSON_PrintUnformatted(client_id);
    cJSON_Delete(client_id);
    if (NULL == _client_id_serialize)
        return IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY;

    LOG_INF("client_id : %s", _client_id_serialize);    

    memset(_messageID, 0, IOTEX_PAL_SPROUT_MESSAGE_ID_MAX_SIZE);

    k_mutex_init(&_sprout_ctx._sprout_mutex);
    k_work_init(&_sprout_ctx.work, _pal_sprout_http_response_parse);

    cJSON *payload_data = cJSON_CreateObject();
    cJSON_AddStringToObject(payload_data, "private_input", "14");
    cJSON_AddStringToObject(payload_data, "public_input", "3.34");
    cJSON_AddStringToObject(payload_data, "receipt_type", "Snark");
    char *payload_data_str = cJSON_PrintUnformatted(payload_data);

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddNumberToObject(payload, "projectID", 21);
    cJSON_AddStringToObject(payload, "projectVersion", "0.1");
    cJSON_AddStringToObject(payload, "data", payload_data_str);
    payload_str = cJSON_PrintUnformatted(payload);
    printf("PayLoad : %s\n", payload_str);       
 
    return IOTEX_SPROUT_ERR_SUCCESS;
}

char *iotex_pal_sprout_message_id_get(void)
{
    if (_messageID[0])
        return _messageID;

    return NULL;        
}

static int _pal_sprout_http_response_recv(struct http_response *rsp, enum http_final_call final_data)
{
    if (NULL == rsp)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    if ((NULL == _sprout_ctx._replyData) && rsp->content_length )
        _sprout_ctx._replyData = calloc(rsp->content_length + 1, 1);

    if (NULL == _sprout_ctx._replyData)
        return IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY;

    if (rsp->body_found) {
        memcpy(_sprout_ctx._replyData + rsp->processed - rsp->body_frag_len, rsp->recv_buf + rsp->data_len - rsp->body_frag_len, rsp->body_frag_len);    
    }

	if (final_data == HTTP_DATA_FINAL) {
        _sprout_ctx.hasFinish = true;
    }

    return IOTEX_SPROUT_ERR_SUCCESS;  
}

static void _response_cb(struct http_response *rsp, enum http_final_call final_data, void *user_data)
{
    int ret = _pal_sprout_http_response_recv(rsp, final_data);
    if (IOTEX_SPROUT_ERR_SUCCESS != ret)
        return;

	if (final_data == HTTP_DATA_MORE) 
        return;
        
    if (0 != strcmp(rsp->http_status, "OK")) {
        _err_times++;      
        LOG_ERR("Response status %s : %s\n", rsp->http_status, _sprout_ctx._replyData);
        return;
    }

    k_work_submit(&_sprout_ctx.work);
        
    return;
}

int iotex_pal_sprout_server_diddoc_get(void)
{
    if (_err_times >= IOTEX_PAL_SPROUT_ERROR_TIMES_MAX)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    if (-1 == _sock)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    LOG_INF("Starting to get DIDDoc of Server");

    _pal_sprout_ctx_deinit();
    _sprout_ctx.type = IOTEX_PAL_SPROUT_CTX_TYPE_SERVER_DIDDOC;        

	struct http_request req = {0};

    req.method          = HTTP_GET;
    req.host            = IOTEX_SPROUT_HTTP_HOST;
    req.url             = IOTEX_SPROUT_HTTP_PATH_GET_DIDDOC;
    req.protocol        = "HTTP/1.1";
    req.response        = _response_cb;
    req.recv_buf        = _replyData;
    req.recv_buf_len    = sizeof(_replyData);

    memset(_replyData, 0, sizeof(_replyData));

    http_client_req(_sock, &req, IOTEX_SPROUT_HTTP_TIMEOUT, "GET_DIDDoc");
	
    return 0;
}

int iotex_pal_sprout_server_request_token(void)
{
    if (_err_times >= IOTEX_PAL_SPROUT_ERROR_TIMES_MAX)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    if (-1 == _sock)
        return IOTEX_SPROUT_ERR_BAD_STATUS;
    
    if (NULL == _deviceDID || NULL == _deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_STATUS;
    
    if (NULL == _client_id_serialize) {
        cJSON * client_id = cJSON_CreateObject();
        if (NULL == client_id)
            return IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY;

        cJSON_AddStringToObject(client_id, "clientID", _deviceDID);
        _client_id_serialize = cJSON_PrintUnformatted(client_id);
        if (NULL == _client_id_serialize)
            return IOTEX_SPROUT_ERR_INSUFFICIENT_MEMORY;

        cJSON_Delete(client_id); 
    }

    LOG_INF("Starting to request token");

    _pal_sprout_ctx_deinit();
    _sprout_ctx.type = IOTEX_PAL_SPROUT_CTX_TYPE_REQUEST_TOKEN;              

	struct http_request req = {0};

    req.method          = HTTP_POST;
    req.url             = IOTEX_SPROUT_HTTP_PATH_REQUEST_TOKEN;
    req.host            = IOTEX_SPROUT_HTTP_HOST;
    req.port            = IOTEX_SPROUT_HTTP_PORT_STRING;
    req.protocol        = "HTTP/1.1";
    req.response        = _response_cb;
    req.recv_buf        = _replyData;
    req.recv_buf_len    = sizeof(_replyData);

    req.payload         = _client_id_serialize;
    req.payload_len     = strlen(_client_id_serialize);
    
    http_client_req(_sock, &req, IOTEX_SPROUT_HTTP_TIMEOUT, "Request_Token");       

    return IOTEX_SPROUT_ERR_SUCCESS;
}

int iotex_pal_sprout_send_message(char *message)
{
    if (_err_times >= IOTEX_PAL_SPROUT_ERROR_TIMES_MAX)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    if (-1 == _sock)
        return IOTEX_SPROUT_ERR_BAD_STATUS;
    
    if (NULL == _deviceDID || NULL == _deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_STATUS + 10;

    if (NULL == message)
        return IOTEX_SPROUT_ERR_BAD_STATUS + 11;
    
    if (0 == _didcommToken[0])
        return IOTEX_SPROUT_ERR_BAD_STATUS + 12;

    LOG_INF("Starting to send message");

    _pal_sprout_ctx_deinit();
    _sprout_ctx.type = IOTEX_PAL_SPROUT_CTX_TYPE_SEND_MESSAGE;    

	struct http_request req = {0};

    req.method          = HTTP_POST;
    req.url             = IOTEX_SPROUT_HTTP_PATH_MESSAGE;
    req.host            = IOTEX_SPROUT_HTTP_HOST;
    req.port            = IOTEX_SPROUT_HTTP_PORT_STRING;
    req.protocol        = "HTTP/1.1";
    req.response        = _response_cb;
    req.recv_buf        = _replyData;
    req.recv_buf_len    = sizeof(_replyData);

    req.payload         = message;
    req.payload_len     = strlen(message);

    req.header_fields = (const char **)_headers;

    int ret = http_client_req(_sock, &req, IOTEX_SPROUT_HTTP_TIMEOUT, "Send_Message");        
    if (ret < 0) {
        LOG_ERR("http_client_req (%d)", ret);
        return ret;
    }

    return IOTEX_SPROUT_ERR_SUCCESS;
}

int iotex_pal_sprout_msg_query(char *message_id)
{
    char message_path[IOTEX_PAL_SPROUT_MESSAGE_ID_MAX_SIZE] = {0};

    if (_err_times >= IOTEX_PAL_SPROUT_ERROR_TIMES_MAX)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    if (-1 == _sock)
        return IOTEX_SPROUT_ERR_BAD_STATUS;
    
    if (NULL == _deviceDID || NULL == _deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    if (NULL == message_id && 0 == _messageID[0])
        return IOTEX_SPROUT_ERR_BAD_STATUS;             
    
    if (0 == _didcommToken[0])
        return IOTEX_SPROUT_ERR_BAD_STATUS;        

    memcpy(message_path, IOTEX_SPROUT_HTTP_MESSAGE_QUERY_PATH_HEAD, strlen(IOTEX_SPROUT_HTTP_MESSAGE_QUERY_PATH_HEAD));
    if (message_id)        
        memcpy(message_path + strlen(IOTEX_SPROUT_HTTP_MESSAGE_QUERY_PATH_HEAD), message_id, strlen(message_id));
    else
        memcpy(message_path + strlen(IOTEX_SPROUT_HTTP_MESSAGE_QUERY_PATH_HEAD), _messageID, strlen(_messageID));
	
    _pal_sprout_ctx_deinit();
    _sprout_ctx.type = IOTEX_PAL_SPROUT_CTX_TYPE_QUERY_STATUS; 

	struct http_request req = {0};

    req.method          = HTTP_GET;
    req.url             = message_path;
    req.host            = IOTEX_SPROUT_HTTP_HOST;
    req.port            = IOTEX_SPROUT_HTTP_PORT_STRING;
    req.protocol        = "HTTP/1.1";
    req.response        = _response_cb;
    req.recv_buf        = _replyData;
    req.recv_buf_len    = sizeof(_replyData);

    req.header_fields = (const char **)_headers;

    http_client_req(_sock, &req, IOTEX_SPROUT_HTTP_TIMEOUT, "Query");

    return IOTEX_SPROUT_ERR_SUCCESS;
}

#if 0
int iotex_pal_sprout_http_server_connect(void)
{
	int fd;
	char *p;
	int bytes;
	size_t off;
	struct addrinfo *res;
	struct addrinfo hints = {
		.ai_flags = AI_NUMERICSERV, /* Let getaddrinfo() set port */
		.ai_socktype = SOCK_STREAM,
	};
	char peer_addr[INET6_ADDRSTRLEN];

    LOG_INF("Looking up %s", IOTEX_SPROUT_HTTP_HOST);
	int err = getaddrinfo(IOTEX_SPROUT_HTTP_HOST, IOTEX_SPROUT_HTTP_PORT_STRING, &hints, &res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return 0;
	}

	inet_ntop(res->ai_family, &((struct sockaddr_in *)(res->ai_addr))->sin_addr, peer_addr,
		  INET6_ADDRSTRLEN);
	printk("Resolved %s (%s) protocol %d\n", peer_addr, net_family2str(res->ai_family), res->ai_protocol);

    _sock = socket(res->ai_family, SOCK_STREAM, res->ai_protocol);

	printk("Connecting to %s:%d\n", IOTEX_SPROUT_HTTP_HOST,
	       ntohs(((struct sockaddr_in *)(res->ai_addr))->sin_port));
	err = connect(_sock, res->ai_addr, res->ai_addrlen);
	if (err) {
		printk("connect() failed, err: %d\n", errno);
		goto clean_up;
	}

    printk("Connected to %s:%d\n", IOTEX_SPROUT_HTTP_HOST, ntohs(((struct sockaddr_in *)(res->ai_addr))->sin_port));    

    return 0;
    
clean_up:
	freeaddrinfo(res);
	(void)close(fd);

	return 0;    
}
#endif

int iotex_pal_sprout_didcomm_prepare(void)
{
    int ret = _pal_sprout_http_server_connect();
    if (ret)
        return ret;

    if (_sock < 0)
        return -1;

    k_mutex_lock(&_sprout_ctx._sprout_mutex, K_NO_WAIT);

    iotex_pal_sprout_server_diddoc_get();

    ret = k_mutex_lock(&_sprout_ctx._sprout_mutex, K_MSEC(5000));
    if (ret) {
        LOG_ERR("Get DIDDoc of Server Timeout");
        ret = IOTEX_SPROUT_ERR_TIMEOUT;
        goto exit;
    }

    iotex_pal_sprout_server_request_token();

exit:
    return ret;
}

int iotex_pal_sprout_didcomm_send_message(char *message)
{
    if (NULL == message)
        return IOTEX_SPROUT_ERR_BAD_INPUT_PARA;

    if (_sock < 0)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    if (NULL == _deviceDID || NULL == _deviceKAKID)
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    if (0 == _serverKAKID[0])
        return IOTEX_SPROUT_ERR_BAD_STATUS;

    char *recipients_kid[JOSE_JWE_RECIPIENTS_MAX] = {0};
    recipients_kid[0] = _serverKAKID;

    char *jwe_json = iotex_jwe_encrypt(message, Ecdh1puA256kw, A256cbcHs512, _deviceDID, NULL, recipients_kid, false);
    if (NULL == jwe_json) {
        LOG_ERR("Failed to Encrypt the message\n");
        return IOTEX_SPROUT_ERR_ENCRYPT_FAIL;
    }

    int ret = iotex_pal_sprout_send_message(jwe_json);
    if (IOTEX_SPROUT_ERR_SUCCESS != ret)
        LOG_ERR("Failed to Send Message to the Server (%d)", ret);
    
    free (jwe_json);

    return ret;
}

int iotex_pal_sprout_loop(void)
{
    int ret = k_mutex_lock(&_sprout_ctx._sprout_mutex, K_MSEC(5000));
    if (ret) {
        LOG_ERR("Get Sprout Mutex Timeout");
        return IOTEX_SPROUT_ERR_TIMEOUT;
    }

    iotex_pal_sprout_didcomm_send_message(payload_str);

    return IOTEX_SPROUT_ERR_SUCCESS;
}
