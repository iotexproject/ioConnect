#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/utils/devRegister/devRegister.h"
#include "include/utils/cJSON/cJSON.h"

#define IOTEX_PSA_KEY_ID_INVALID            0
#define IOTEX_PSA_KEY_ID_DEFAULT            1

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

#if 0
static void hex2str(char *buf_hex, int len, char *str)
{
    int        i, j;
    const char hexmap[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for (i = 0, j = 0; i < len; i++) {
        str[j++] = hexmap[buf_hex[i] >> 4];
        str[j++] = hexmap[buf_hex[i] & 0x0F];
    }

    str[j] = 0;
}
#endif

static int hexStr2Bin(char *str, char *bin) {
	
    int i,j;
    for(i = 0,j = 0; j < (strlen(str)>>1) ; i++,j++) {
        bin[j] = (str2Hex(str[i]) <<4);
        i++;
        bin[j] |= str2Hex(str[i]);
    }

    return j; 
}

static void iotex_utils_convert_hex_to_str(const unsigned char *hex, size_t hex_size, char *output) 
{
    for (size_t i = 0; i < hex_size; ++i) {
        sprintf(output + (i * 2), "%02x", hex[i]);
    }

    output[hex_size * 2] = '\0';
}

char * iotex_utils_device_register_did_upload_prepare(char *did, psa_key_id_t keyid, char *signature_context, bool format)
{
    char *did_serialize = NULL;

    uint8_t signature[64];
    char signature_str[64 * 2 + 1] = {0};

    uint8_t puk[64] = {0};
    char puk_str[64 * 2 + 4 + 1] = {0};

    size_t puk_length = 0;

    puk_str[0] = '0';
    puk_str[1] = 'x';
    puk_str[2] = '0';
    puk_str[3] = '4';
    
    if (NULL == did)
        return NULL;
    
    if (IOTEX_PSA_KEY_ID_INVALID == keyid)
        keyid = IOTEX_PSA_KEY_ID_DEFAULT;
    
    cJSON *did_root = cJSON_CreateObject();
    if (NULL == did_root)
        return NULL;
    
    cJSON_AddStringToObject(did_root, "did", did);

    psa_status_t status = psa_export_public_key( keyid, (uint8_t *)puk, sizeof(puk), &puk_length );
    if (PSA_SUCCESS != status)
        goto exit;
    
    iotex_utils_convert_hex_to_str(puk , puk_length, puk_str + 4);

    cJSON_AddStringToObject(did_root, "puk", puk_str);
    cJSON_AddStringToObject(did_root, "project_name", IOTEX_PAL_DEVICE_REGISTER_UPLOAD_DID_PROJECT_NAME);

    memset(signature_str, 0, sizeof(signature_str));

    if (signature_context) {

        strcpy(signature_str, signature_context);

    } else {

        uint8_t hash[32];
        size_t  hash_size = 0;
        psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
        
        psa_hash_setup(&operation, PSA_ALG_SHA_256);
        psa_hash_update(&operation, did, strlen(did));
        psa_hash_update(&operation, puk_str, strlen(puk_str));
        psa_hash_finish(&operation, hash, sizeof(hash), &hash_size);
        
        size_t  signature_length;
        status = psa_sign_hash(keyid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_size, signature, sizeof(signature), &signature_length);
        if (PSA_SUCCESS != status)
            goto exit;
        
        iotex_utils_convert_hex_to_str(signature , signature_length, signature_str);   

    }
     
    cJSON_AddStringToObject(did_root, "signature", signature_str);

    if (format) {
        did_serialize = cJSON_Print(did_root);
    } else {
        did_serialize = cJSON_PrintUnformatted(did_root);
    }
    
exit:
    cJSON_Delete(did_root);

    return did_serialize;    
}

char * iotex_utils_device_register_diddoc_upload_prepare(char *diddoc, psa_key_id_t keyid, char *signature_context, bool format)
{
    char *diddoc_serialize = NULL;

    uint8_t signature[64];
    char signature_str[64 * 2 + 1] = {0};

    if (NULL == diddoc)
        return NULL;

    if (IOTEX_PSA_KEY_ID_INVALID == keyid)
        keyid = IOTEX_PSA_KEY_ID_DEFAULT;

    cJSON *diddoc_root = cJSON_CreateObject();
    if (NULL == diddoc_root)
        return NULL;

    cJSON *diddoc_item = cJSON_Parse(diddoc);
    if (NULL == diddoc_item)
        goto exit;

    cJSON_AddItemToObject(diddoc_root, "diddoc", diddoc_item);

    if (signature_context) {

        strcpy(signature_str, signature_context);

    } else {    

        size_t signature_length = 0;
        psa_status_t status =  psa_sign_message(keyid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), diddoc, strlen(diddoc), signature, 64, &signature_length);
        if (status != PSA_SUCCESS)
            goto exit;

        iotex_utils_convert_hex_to_str(signature , signature_length, signature_str);

    }

    cJSON_AddStringToObject(diddoc_root, "signature", signature_str);

    if (format) {
        diddoc_serialize = cJSON_Print(diddoc_root);
    } else {
        diddoc_serialize = cJSON_PrintUnformatted(diddoc_root);
    }    

exit:
    cJSON_Delete(diddoc_root);

    return diddoc_serialize;
}

char * iotex_utils_device_register_signature_response_prepare(char *buf, psa_key_id_t keyid)
{
    char *sign_serialize = NULL;
    char signature_str[64 * 2 + 2 + 1] = {0};
    uint8_t hexbin[128] = {0};

    if (NULL == buf)
        return NULL;

    if (IOTEX_PSA_KEY_ID_INVALID == keyid)
        keyid = IOTEX_PSA_KEY_ID_DEFAULT;
    
    cJSON *hex_root = cJSON_Parse(buf);
    if (NULL == hex_root)
        return NULL;
    
    cJSON *hex_item = cJSON_GetObjectItem(hex_root, "hex");
    if (NULL == hex_item || !cJSON_IsString(hex_item))
        goto exit;

    char *hex_str = hex_item->valuestring;
    if(hex_str[0] != '0' || hex_str[1] != 'x')
        goto exit;

    int hexbin_len = hexStr2Bin(hex_str + 2, (char *)hexbin);
    
    uint8_t signature[64];
    size_t  signature_length;
    psa_status_t status = psa_sign_hash(keyid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hexbin, hexbin_len, signature, sizeof(signature), &signature_length);
    if (PSA_SUCCESS != status)
        goto exit;

    signature_str[0] = '0';
    signature_str[1] = 'x';

    iotex_utils_convert_hex_to_str(signature , signature_length, signature_str + 2);        

    cJSON *sign = cJSON_CreateObject();
    if (NULL == sign)
        goto exit;

    cJSON_AddStringToObject(sign, "sign", signature_str);

    sign_serialize = cJSON_Print(sign);

    cJSON_Delete(sign);

exit:
    cJSON_Delete(hex_root); 

    return sign_serialize;    
}