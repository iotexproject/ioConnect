#include <string.h>
#include "include/server/crypto.h"
#include "include/dids/didcomm/message.h"
#include "include/dids/didcomm/envelope.h"
#include "include/dids/didcomm/encrypted.h"
#include "include/jose/jws.h"
#include "include/jose/jwe.h"
#include "include/utils/cJSON/cJSON.h"
#include "include/utils/baseX/base64.h"

char *did_or_url(char *str)
{
    int idx = 0;

    if (NULL == str)
        return NULL;

    for (int i = 0; i < strlen(str); i++) {
        if (str[idx] == '#') {
            idx = i;
            break;
        }            
    }

    if (0 == idx) 
        return NULL;

    char *did = malloc(idx + 1);
    if (NULL == did)
        return NULL;
    memset(did, 0, idx + 1);

    memcpy(did, str, idx);

    return did;         
}

static int _is_did(char *str)
{
    if (NULL == str)
        return -1;

    if (strlen(str) < 3)
        return -2;

    if (strncmp(str, "did", 3))
        return -3;

    return 0;    
}

static int _validate_pack_signed(char *sign_by)
{
    return _is_did(sign_by);
}

#if 0
static int __validate_pack_encrypted(Message *msg, char *to, char *from, char *sign_by)
{
    int ret = 0, isContained = 0;
    int to_did_needfree = 0, from_did_needfree = 0;
    char *from_did = NULL, *to_did = NULL;

    if (NULL == msg)
        return -1;

    if (_is_did(to))
        return -1;

    if ((from) && (_is_did(from))) 
        return -2;

    if ((sign_by) && (_is_did(sign_by))) 
        return -3;

    to_did = did_or_url(to);
    if (NULL == to_did) 
        to_did = to;
    else
        to_did_needfree = 1;

    for (int i = 0; i < 4; i++) {
        if ((msg->to[i]) && (0 == strcmp(msg->to[i], to_did))) {
            isContained = 1;
            break;
        }
    }

    if (0 == isContained) {
        ret = -4;
        goto exit;
    }

    if (NULL == from || NULL == msg->from)
        goto exit;

    from_did = did_or_url(from);
    if (NULL == from_did)
        from_did = from;
    else
        from_did_needfree = 1;

    if (strcmp(msg->from, from_did)) {
        ret = -5;
    }    

exit:
    if ((to_did_needfree) && (to_did))
        free(to_did);  

    if ((from_did_needfree) && (from_did))
        free(from_did);

    return ret;            
}
#endif

#if 0
static char *_envelope_jwe_protectedheader_serialize(JweProtectedHeader *header)
{
    char *output = NULL;
    cJSON *json_header = NULL;
    
    if (NULL == header)
        return NULL;
    
    if (NULL == header->typ)
        return NULL;        
    
    json_header = cJSON_CreateObject();

    cJSON_AddStringToObject(json_header, "typ", header->typ);

    switch (header->alg) {
        case EdDSA:
    
            cJSON_AddStringToObject(json_header, "alg", "EdDSA");
            break;
        case ES256:
    
            cJSON_AddStringToObject(json_header, "alg", "Es256");
            break;
        case ES256K:
    
            cJSON_AddStringToObject(json_header, "alg", "Es256K");
            break;           
        default:
    
            cJSON_Delete(json_header);
            return NULL;
    }    

    output = cJSON_Print(json_header);

    cJSON_Delete(json_header);

    return output;
}
#endif

static char *_envelope_jws_protectedheader_serialize(JWSProtectedHeader *header)
{
    char *output = NULL;
    cJSON *json_header = NULL;
    
    if (NULL == header)
        return NULL;
    
    if (0 == header->typ[0])
        return NULL;        
    
    json_header = cJSON_CreateObject();

    cJSON_AddStringToObject(json_header, "typ", header->typ);

    switch (header->alg) {
        case EdDSA:
            cJSON_AddStringToObject(json_header, "alg", "EdDSA");
            break;
        case ES256:
            cJSON_AddStringToObject(json_header, "alg", "Es256");
            break;
        case ES256K:
            cJSON_AddStringToObject(json_header, "alg", "Es256K");
            break;           
        default:
            cJSON_Delete(json_header);
            return NULL;
    }    

    output = cJSON_Print(json_header);

    cJSON_Delete(json_header);

    return output;
}

static char *_envelope_jws_serialize(JWS *jws)
{
    int jws_valid = 0;

    cJSON *jws_json = NULL;
    cJSON *header_json = NULL;
    cJSON *signature_json = NULL;
    cJSON *signatures_json = NULL;

    if (NULL == jws)
        return NULL;

    for (int i = 0; i < 4; i++) {
        if (jws->signatures[i])
            jws_valid++;
    }

    if (0 == jws_valid)
        return NULL;

    if (NULL == jws->payload)
        return NULL;

    jws_json = cJSON_CreateObject();

    cJSON_AddStringToObject(jws_json, "payload", jws->payload);                   

    header_json = cJSON_CreateObject();
    cJSON_AddStringToObject(header_json, "kid", jws->signatures[0]->header->kid);

    signature_json = cJSON_CreateObject();
    cJSON_AddStringToObject(signature_json, "protected", jws->signatures[0]->_protected);
    cJSON_AddStringToObject(signature_json, "signature", jws->signatures[0]->signature);
    cJSON_AddItemToObject(signature_json, "header", header_json);

    signatures_json = cJSON_CreateArray();
    cJSON_AddItemToArray(signatures_json, signature_json);
    cJSON_AddItemToObject(jws_json, "signatures", signatures_json);

    char *output = cJSON_Print(jws_json);

    // cJSON_Delete(signature_json);
    // cJSON_Delete(signatures_json);
    // cJSON_Delete(header_json);
    // cJSON_Delete(jws_json);

    return output;
}

Attachment *attachment_new(AttachmentData *data)
{
    Attachment *attachment = NULL;

    if (NULL == data)
        return NULL;

    attachment = (Attachment *)malloc(sizeof(Attachment));
    if (NULL == attachment)
        return NULL;

    memset(attachment, 0, sizeof(Attachment));
    memcpy(&attachment->data, data, sizeof(AttachmentData));

    return attachment;        
}

Attachment *attachment_set_id(Attachment *attachment, char *id)
{
    if (NULL == attachment || NULL == id)
        return NULL;

    if (attachment->id)
        free(attachment->id);

    attachment->id = id;

    return attachment;
}

Attachment *attachment_set_description(Attachment *attachment, char *description)
{
    if (NULL == attachment || NULL == description)
        return NULL;

    if (attachment->description)
        free(attachment->description);

    attachment->description = description;

    return attachment;
}

Attachment *attachment_set_filename(Attachment *attachment, char *filename)
{
    if (NULL == attachment || NULL == filename)
        return NULL;

    if (attachment->filename)
        free(attachment->filename);

    attachment->filename = filename;

    return attachment;
}

Attachment *attachment_set_media_type(Attachment *attachment, char *media_type)
{
    if (NULL == attachment || NULL == media_type)
        return NULL;

    if (attachment->media_type)
        free(attachment->media_type);

    attachment->media_type = media_type;

    return attachment;
}

Attachment *attachment_set_format(Attachment *attachment, char *format)
{
    if (NULL == attachment || NULL == format)
        return NULL;

    if (attachment->format)
        free(attachment->format);

    attachment->format = format;

    return attachment;
}

Attachment *attachment_set_lastmod_time(Attachment *attachment, time_t lastmod_time)
{
    if (NULL == attachment)
        return NULL;

    attachment->lastmod_time = lastmod_time;

    return attachment;
}

Attachment *attachment_set_byte_count(Attachment *attachment, unsigned int byte_count)
{
    if (NULL == attachment)
        return NULL;

    attachment->byte_count = byte_count;

    return attachment;
}

Attachment *attachment_set_jws(Attachment *attachment, char *jws, AttachmentData_Type type)
{
    if (NULL == attachment || NULL == jws)
        return NULL;    

    switch (type)
    {
    case AttachmentData_Base64:
        attachment->data.data.base64_data.jws = jws;
        break;
    case AttachmentData_Json:
        attachment->data.data.json_data.jws = jws;
        break;
    case AttachmentData_Links:
        attachment->data.data.link_data.jws = jws;
        break;                
    
    default:
        return NULL;
    }        

    attachment->data.type = type;

    return attachment;
}

AttachmentData *attachmentdata_new_base64(char *base64)
{
    AttachmentData *attachmentdata = NULL;

    if (NULL == base64)
        return NULL;

    attachmentdata = malloc(sizeof(AttachmentData));
    if (NULL == attachmentdata)
        return NULL;

    memset(attachmentdata, 0, sizeof(AttachmentData));

    attachmentdata->type = AttachmentData_Base64;
    attachmentdata->data.base64_data.base64 = base64;

    return attachmentdata;            
}

AttachmentData *attachmentdata_new_json(unsigned int json_type, void *json)
{
    AttachmentData *attachmentdata = NULL;

    if (NULL == json)
        return NULL;

    attachmentdata = malloc(sizeof(AttachmentData));
    if (NULL == attachmentdata)
        return NULL;
        
    memset(attachmentdata, 0, sizeof(AttachmentData));

    attachmentdata->type = AttachmentData_Json;
    attachmentdata->data.json_data.json_type = json_type;
    attachmentdata->data.json_data.json = json;

    return attachmentdata;            
}

Message *message_new(char *id, char *type_, unsigned int body_type, void *body)
{
    Message *message = NULL;

    if (NULL == id || NULL == type_ || NULL == body)
        return NULL;

    message = malloc(sizeof(Message));
    if (NULL == message)
        return NULL;

    memset(message, 0, sizeof(Message));

    message->id = id;
    message->type = type_;
    message->body_type = body_type;
    message->body = body;

    return message;         
}

Message *message_set_to(Message *message, char *to)
{
    int i;

    if (NULL == message || NULL == to)
        return NULL;

    for (i = 0; i < 4; i++) {
        if(NULL == message->to[i])
            break;
    }

    if (i >= 4)
        return NULL;

    message->to[i] = to;

    return message;
}

Message *message_set_from(Message *message, char *from)
{
    if (NULL == message || NULL == from)
        return NULL;

    if (message->from)
        free(message->from);   

    message->from = from;

    return message;             
}

Message *message_set_thid(Message *message, char *thid)
{
    if (NULL == message || NULL == thid)
        return NULL;

    if (message->thid)
        free(message->thid);   

    message->thid = thid;

    return message;             
}

Message *message_set_pthid(Message *message, char *pthid)
{
    if (NULL == message || NULL == pthid)
        return NULL;

    if (message->pthid)
        free(message->pthid);   

    message->pthid = pthid;

    return message;             
}

Message *message_set_created_time(Message *message, time_t created_time)
{
    if (NULL == message)
        return NULL;

    message->created_time = created_time;

    return message;             
}

Message *message_set_expires_time(Message *message, time_t expires_time)
{
    if (NULL == message)
        return NULL;

    message->expires_time = expires_time;

    return message;             
}

Message *message_set_from_prior(Message *message, char *from_prior)
{
    if (NULL == message || NULL == from_prior)
        return NULL;

    if (message->from_prior)
        free(message->from_prior);   

    message->from_prior = from_prior;

    return message;             
}

Message *message_set_attachment(Message *message, Attachment *attachment)
{
    int i;

    if (NULL == message || NULL == attachment)
        return NULL;

    for (i = 0; i < 4; i++) {
        if(NULL == message->attachments[i])
            break;
    }

    if (i >= 4)
        return NULL;

    message->attachments[i] = attachment;

    return message;
}

char *didcomm_message_pack_plaintext(Message *message)
{
    char *plaintext = NULL;
    cJSON *plaintext_json = NULL;

    if (NULL == message)
        return NULL;

    if (NULL == message->id || NULL == message->type)
        return NULL;

    plaintext_json = cJSON_CreateObject();

    cJSON_AddStringToObject(plaintext_json, "id", message->id);
    
    if (message->typ)
        cJSON_AddStringToObject(plaintext_json, "typ", message->typ);
    
    cJSON_AddStringToObject(plaintext_json, "type", message->type);
    
    if (message->from)
        cJSON_AddStringToObject(plaintext_json, "from", message->from);
    
    int used_num = 0;
    for (int i = 0; i < 4; i++) {
        if (message->to[i]) 
            used_num++;
    }

    if (used_num) {
        cJSON *to_json = cJSON_CreateArray();

        for (int i = 0; i < 4; i++) {
            if (message->to[i]) {
                cJSON_AddItemToArray(to_json, cJSON_CreateString(message->to[i]));
            }
        }

        cJSON_AddItemToObject(plaintext_json, "to", to_json);
    }

    if (message->thid)
        cJSON_AddStringToObject(plaintext_json, "thid", message->thid);   

    if (message->pthid)
        cJSON_AddStringToObject(plaintext_json, "pthid", message->pthid); 

    if (message->created_time)
        cJSON_AddNumberToObject(plaintext_json, "created_time", message->created_time);

    if (message->expires_time)
        cJSON_AddNumberToObject(plaintext_json, "expires_time", message->expires_time);

    if (message->from_prior)
        cJSON_AddStringToObject(plaintext_json, "from_prior", message->from_prior);

    if (message->body)
        cJSON_AddItemToObject(plaintext_json, "body", (cJSON *)message->body);

    plaintext =  cJSON_Print(plaintext_json);

    // cJSON_Delete(plaintext_json);   

    return plaintext;
}

char *didcomm_message_pack_signed(Message *message, char *sign_by, JWK *jwk)
{
    char *payload = NULL;
    char *msg = NULL;

    char *base64url_header = NULL;
    size_t  base64url_header_len;
    char *base64url_payload = NULL;
    size_t  base64url_payload_len;
    char *base64url_signature = NULL;
    size_t  base64url_signature_len;    

    unsigned char signature[64] = {0};
    size_t actual_len = 0;
    
    if (NULL == sign_by || NULL == jwk)
        return NULL;
    
    if (_validate_pack_signed(sign_by))
        return NULL;
    
    payload = didcomm_message_pack_plaintext(message);
    if (NULL == payload)
        return NULL;
    
    JWSProtectedHeader protectedheader;
    memset(&protectedheader, 0, sizeof(JWSProtectedHeader));
    memcpy(protectedheader.typ, JOSE_HEADER_TYPE_SIGN_TYPE, strlen(JOSE_HEADER_TYPE_SIGN_TYPE));
    
    if (jwk->type == JWKTYPE_EC) {
        if (0 == strcmp(jwk->Params.ec.crv, "secp256k1"))
            protectedheader.alg = ES256K;
        else if (0 == strcmp(jwk->Params.ec.crv, "P-256"))
            protectedheader.alg = ES256;
    }

    char *header = _envelope_jws_protectedheader_serialize(&protectedheader);
    if (NULL == header)
        return NULL;

    base64url_header_len = BASE64_ENCODE_GETLENGTH(strlen(header));   
    base64url_header = malloc(base64url_header_len);
    if (NULL == base64url_header)
        return NULL;
    memset(base64url_header, 0, base64url_header_len);
    base64url_encode(header, strlen(header), base64url_header, &base64url_header_len);

    base64url_payload_len = BASE64_ENCODE_GETLENGTH(strlen(payload));
    base64url_payload = malloc(base64url_payload_len);
    if (NULL == base64url_payload) {
        free(base64url_header);
        return NULL;
    }
    memset(base64url_payload, 0, base64url_payload_len);
    base64url_encode(payload, strlen(payload), base64url_payload, &base64url_payload_len);    

    int sign_input_len = base64url_header_len + base64url_payload_len + 1 + 1;
    char *sign_input = malloc(sign_input_len);
    if (NULL == sign_input) {
        free(base64url_header);
        free(base64url_payload);
        return NULL;
    }
    memset(sign_input, 0, sign_input_len);

    memcpy(sign_input, base64url_header, strlen(base64url_header));
    sign_input[strlen(base64url_header)] = '.';
    memcpy(sign_input + strlen(base64url_header) + 1, base64url_payload, strlen(base64url_payload));

    psa_sign_message(1, PSA_ALG_ECDSA(PSA_ALG_SHA_256), (const uint8_t *)sign_input, sign_input_len, signature, 64, &actual_len);
    
    base64url_signature_len = BASE64_ENCODE_GETLENGTH(actual_len);
    base64url_signature = malloc(base64url_signature_len);
    if (NULL == base64url_signature) {
        free(base64url_header);
        free(base64url_payload);
        free(sign_input);
        return NULL;
    }
    memset(base64url_signature, 0, base64url_signature_len);
    base64url_encode((const char *)signature, actual_len, base64url_signature, &base64url_signature_len);

    JWSHeader sig_header;
    sig_header.kid = sign_by;
    
    JWSSignature sig_signature;
    sig_signature.header = &sig_header;
    sig_signature._protected = base64url_header;
    sig_signature.signature = base64url_signature;

    JWS jws;
    jws.signatures[0] = &sig_signature;
    jws.payload = base64url_payload;

    msg = _envelope_jws_serialize(&jws);
    
    return msg;
}

static char *_authcrypt(char *msg, char *from, char *to, PackEncryptedOptions *option, JWK *jwk)
{
    enum KnownKeyAlg keyalg;
    char *auth_msg = NULL;
    
    if (NULL == msg)
        return NULL;
    
    if (NULL == option || NULL == jwk)
        return NULL;
    
    keyalg = iotex_jwk_get_key_alg(jwk);
    if (P256 == keyalg || K256 == keyalg) {

        char * recipients[JOSE_JWE_RECIPIENTS_MAX] = {0};

        // TODO: 
        recipients[0] = to;
        
        auth_msg = iotex_jwe_encrypt(msg, Ecdh1puA256kw, A256cbcHs512, from, jwk, recipients, false);
    }

    return auth_msg;
}

char *didcomm_message_pack_encrypted(Message *message, char *from, char *to, char *sign_by, PackEncryptedOptions *option, JWK *jwk)
{
    char *msg = NULL, *encrypted_msg = NULL;
    
    if (NULL == message)
        return NULL;
    
    if (_is_did(from) || _is_did(to))
        return NULL;
    
    if (sign_by)
        msg = didcomm_message_pack_signed(message, sign_by, jwk);
    else
        msg = didcomm_message_pack_plaintext(message);
    if (NULL == msg)
        return NULL;             

    if (from)
        encrypted_msg = _authcrypt(msg, from, to, option, jwk);
    // else 
    //     // TODO: anoncrypt

    return encrypted_msg;                   
}

#include "include/backends/tinycryt/ecc.h"
#include "include/backends/tinycryt/ecc_dh.h"

int message_encrypt_test(char *plaintext)
{
    psa_status_t status;
    uint8_t cekey[32] = {0}, nonce[13] = {0};;
    char *recipients_kid[4] = {0};
    size_t clen = 0;
    JWK *epk = NULL;
    psa_key_id_t cekey_id, wrap_id; 

    recipients_kid[0] = "did:example:bob#key-p256-1";
    
    status =  psa_generate_random( cekey, sizeof(cekey) );
    
    // epk = generate_secp256r1_from_private(cekey);
    unsigned int key_id = 1; 
    epk = iotex_jwk_generate_by_secret(cekey, sizeof(cekey), JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                                        PSA_KEY_LIFETIME_VOLATILE,
                                        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                                        PSA_ALG_ECDSA(PSA_ALG_SHA_256), &key_id);

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_bits(&attributes, 256); 
    
    status = psa_import_key( &attributes, cekey, 32, &cekey_id );      
    printf("cekey_id %x\n", cekey_id);
    
    char *protected = iotex_jwe_encrypt_protected(Ecdh1puA256kw, A256cbcHs512, "did:example:alice#key-p256-1", recipients_kid, epk);
    if (protected)
        printf("protected : %s\n", protected);

    int nonce_length = PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CCM);
    status =  psa_generate_random( nonce, nonce_length );
    
    char *ciphertext = iotex_jwe_encrypt_plaintext(cekey_id, plaintext, strlen(plaintext), (char *)nonce, nonce_length, protected, strlen(protected), &clen);

    if (NULL == ciphertext)
        return -1;

    char *cipher_base64url = base64_encode_automatic(ciphertext, strlen(plaintext));
    if (cipher_base64url) {
        printf("cipher : %s\n", cipher_base64url);
    }
    char *tag_base64url    = base64_encode_automatic(ciphertext + strlen(plaintext), clen - strlen(plaintext));
    if (tag_base64url) {
        printf("tag : %s\n", tag_base64url);
    }
    char *iv_base64url     = base64_encode_automatic((const char *)nonce, nonce_length);
    if (iv_base64url) {
        printf("iv : %s\n", iv_base64url);
    }

	uint8_t private1[32] = {0};
	// uint8_t private2[32] = {0}; 
	uint8_t public1[2*32] = {0};
	// uint8_t public2[2*32] = {0};    
	uint8_t secret1[32] = {0};
	// uint8_t secret2[32] = {0};  

	uECC_Curve curve = uECC_secp256r1();

    if (!uECC_make_key(public1, private1, curve)) {
        printf("make key failed\n");
        return -2;
    }

    if (!uECC_shared_secret(public1, cekey, secret1, curve)) {
        printf("shared_secret() failed (1)\n");
        return -3;
    }

    char *wkey = malloc(32 + 16);
    size_t wkey_len = 0;

    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    status = psa_import_key( &attributes, secret1, 32, &wrap_id );  
    if (PSA_SUCCESS != status)
        return -3;
    
    status = psa_cipher_encrypt(wrap_id, PSA_ALG_CBC_NO_PADDING, cekey, 32, (uint8_t *)wkey, 32 + 16, &wkey_len);
    if (PSA_SUCCESS != status)
        return -4;
    
    char *wkey_base64url = base64_encode_automatic(wkey, 32 + 16);
    if (wkey_base64url)
        printf("wkey : %s\n", wkey_base64url);     

    Recipient recipient;
    recipient.header.kid = "did:example:bob#key-p256-1";
    recipient.encrypted_key = wkey_base64url;

    cJSON *header_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(header_obj, "kid", recipient.header.kid);

    cJSON *recipient_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(recipient_obj, "encrypted_key", recipient.encrypted_key);
    cJSON_AddItemToObject(recipient_obj, "header", header_obj);

    cJSON *recipients_obj = cJSON_CreateArray();
    cJSON_AddItemToArray(recipients_obj, recipient_obj);

    cJSON *encrypt_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(encrypt_obj, "ciphertext", cipher_base64url);
    cJSON_AddStringToObject(encrypt_obj, "protected", protected);
    cJSON_AddItemToObject(encrypt_obj, "recipients", recipients_obj);
    cJSON_AddStringToObject(encrypt_obj, "tag", tag_base64url);
    cJSON_AddStringToObject(encrypt_obj, "iv", iv_base64url);

    char *encrypt_str = cJSON_Print(encrypt_obj);
    if (encrypt_str)
        printf("Encrypt : %s\n", encrypt_str);

    return 0;
}

