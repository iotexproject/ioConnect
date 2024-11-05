#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <microhttpd.h>

#include "include/jose/jose.h"
#include "include/dids/dids.h"

#include "include/utils/convert/convert.h"
#include "include/utils/devRegister/devRegister.h"

#define PORT 8000

#define GET    0
#define POST   1
 
static char * upload_did = NULL;
static char * upload_diddoc = NULL;

static uint8_t secret[32] = {0x57, 0x81, 0x5e, 0x3d, 0x20, 0x9a, 0x42, 0x8d, 0x48, 0x44, 0x83, 0xcc, 0x1a, 0x2c, 0x5b, 0x5d, 0x97, 0x00, 0x7d, 0x5f, 0x17, 0xff, 0xc0, 0xd4, 0xee, 0xd6, 0x03, 0xa4, 0x08, 0x55, 0x03, 0x9e};

static psa_key_id_t device_register_key_id = 0;
static uint8_t signature[64] = {0};
static char    signature_str[64 * 2 + 1] = {0};


static char post_buf[1024] = {0};

struct connection_info_struct {
    int connectiontype;
    struct MHD_PostProcessor *postprocessor;
    char *post_data;
    size_t post_data_size;
};

 static void request_completed (void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe)
 {
    struct connection_info_struct *con_info = *con_cls;
    (void) cls;         /* Unused. Silent compiler warning. */
    (void) connection;  /* Unused. Silent compiler warning. */
    (void) toe;         /* Unused. Silent compiler warning. */
    
    if (NULL == con_info)
        return;
    
    if (con_info->connectiontype == POST) {
        MHD_destroy_post_processor (con_info->postprocessor);
        if (con_info->post_data)
            free (con_info->post_data);
    }

    free (con_info);
    *con_cls = NULL;
}

static int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key, const char *filename,
                        const char *content_type, const char *transfer_encoding, const char *data, uint64_t off, size_t size) {
    struct connection_info_struct *con_info = coninfo_cls;

    if (size > 0) {
        con_info->post_data = realloc(con_info->post_data, con_info->post_data_size + size + 1);
        if (con_info->post_data == NULL) {
            fprintf(stderr, "Failed to allocate memory for post data\n");
            return MHD_NO;
        }
        memcpy(con_info->post_data + con_info->post_data_size, data, size);
        con_info->post_data_size += size;
        con_info->post_data[con_info->post_data_size] = '\0';
    }

    return MHD_YES;
}

static enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                const char *url, const char *method, const char *version,
                                const char *upload_data, size_t *upload_data_size, void **con_cls) {

    struct MHD_Response *response;
    int ret = 0;

    printf ("New %s request for %s using version %s\n", method, url, version);   

    if (0 == strcmp(method, "OPTIONS")) {

        response = MHD_create_response_from_buffer(0, (void *)"", MHD_RESPMEM_PERSISTENT);
        if (!response) return MHD_NO;

        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "*");

        ret = MHD_queue_response(connection, MHD_HTTP_NO_CONTENT, response);

        MHD_destroy_response(response);

        return ret;
    }

    if (0 == strcmp (method, "GET")) {

        if (0 == strcmp (url, "/did")) {
        
            response = MHD_create_response_from_buffer(strlen(upload_did), (void *)upload_did, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
            MHD_add_response_header(response, "Content-Type", "application/json");
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);

        } else if (0 == strcmp (url, "/diddoc")) {
            printf ("Receive GET DIDDoc\n");

            response = MHD_create_response_from_buffer(strlen(upload_diddoc), (void *)upload_diddoc, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
            MHD_add_response_header(response, "Content-Type", "application/json");
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);

        } else {
            printf ("Receive GET Unsupport\n");
        }

        return ret;
    }         

    struct connection_info_struct *con_info;

    if (0 == strcmp(method, "POST")) {

        if (NULL == *con_cls) {
            con_info = malloc(sizeof(struct connection_info_struct));
            if (NULL == con_info) {
                printf("Failed to malloc struct connection_info_struct\n");
                return MHD_NO;
            }

            con_info->post_data = NULL;
            con_info->post_data_size = 0;

            con_info->postprocessor = MHD_create_post_processor(connection, 1024, iterate_post, (void *)con_info);
            if (NULL == con_info->postprocessor) {
                printf("Failed to create a post_processor\n");
                // free(con_info);
                // return MHD_NO;
            }

            *con_cls = (void *)con_info;
        
            return MHD_YES;
        }

        con_info = *con_cls;
        
        if (*upload_data_size != 0) {

            memcpy(post_buf, upload_data, *upload_data_size);
            
            // MHD_post_process(con_info->postprocessor, upload_data, *upload_data_size);
            *upload_data_size = 0;
            
            return MHD_YES;

        } else {

            char *sign = iotex_utils_device_register_signature_response_prepare(post_buf, 1);
            if (sign)
                printf("%s\n", sign);
            else
                return MHD_NO;

            response = MHD_create_response_from_buffer(strlen(sign), (void *)sign, MHD_RESPMEM_PERSISTENT);
            if (NULL == response) {
                return MHD_NO;
            }

            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
            MHD_add_response_header(response, "Content-Type", "application/json");

            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

            MHD_destroy_response(response);            
        }
    }
    
    return ret;
}

static void _pal_device_register_init_0(void)
{
    if (upload_did) 
        free(upload_did);

    if (upload_diddoc)
        free(upload_diddoc);

    upload_did      = NULL;
    upload_diddoc   = NULL;

    if (device_register_key_id) {
        psa_destroy_key(device_register_key_id);
	    device_register_key_id = 0;        
    }

    memset(signature, 0, sizeof(signature)); 
    memset(signature_str, 0, sizeof(signature_str));
}

static int _pal_device_register_init(char *did)
{
    if (NULL == did)
        return -1;

    _pal_device_register_init_0();

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_bits(&attributes, 256);

    psa_status_t status = psa_import_key( &attributes, secret, sizeof(secret), &device_register_key_id );
    if (PSA_SUCCESS != status)
        return -2;

	static size_t  signature_length = 0;
    status = psa_sign_message(device_register_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), did, strlen(did), signature, sizeof(signature), &signature_length);
	if (PSA_SUCCESS != status)
		return -3;

	iotex_utils_convert_hex_to_str(signature , signature_length, signature_str);

    return 0;
}

void iotex_pal_sprout_device_register_start(char *did, char *diddoc)
{
    if (NULL == did || NULL == diddoc)
        return;
    
    int ret = _pal_device_register_init(did);
    if (ret) {
        printf("Failed to _pal_device_register_init() ret %d\n", ret);
    }

    upload_did    = iotex_utils_device_register_did_upload_prepare(did, 1, signature_str, true);
    if (upload_did)
        printf("Upload DID : %s\n", upload_did);

    upload_diddoc = iotex_utils_device_register_diddoc_upload_prepare(diddoc, 1, signature_str, true);
    if (upload_diddoc)
        printf("Upload DIDDoc : %s\n", upload_diddoc);  

    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
                              &answer_to_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL, MHD_OPTION_END);
    if (NULL == daemon) 
        return;

    printf("HTTP server running on port %d\n", PORT);    
}

void iotex_pal_sprout_device_register_stop(void)
{
    _pal_device_register_init_0();
}



