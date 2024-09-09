#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "include/server/crypto.h"
#include "include/jose/jws.h"
#include "include/jose/jwk.h"
#include "include/jose/jwe.h"
#include "include/dids/did/registry.h"
#include "include/utils/baseX/base64.h"

static char *_jwe_enc_algorithm_as_str(enum EncAlgorithm alg)
{
    switch (alg) {
        case A256cbcHs512:
            return "A256CBC-HS512";
        case Xc20P:
            return "XC20P";
        case A256Gcm:
            return "A256GCM";                
    }

    return NULL;
}

static char *_jwe_kw_algorithm_as_str(enum KWAlgorithms alg)
{
    switch (alg) {
        case Ecdh1puA256kw:
            return "ECDH-1PU+A256KW";
        case EcdhEsA256kw:
            return "ECDH-ES+A256KW";             
    }

    return NULL;
}

static int _find_recipients_num(char *recipients_kid[4], unsigned int *kid_len)
{
    int num = 0, len = 0;

    for (int i = 0; i < 4; i++) {
        if (recipients_kid[i]) {
            len += strlen(recipients_kid[i]);
            num++;
        }
    }

    if (kid_len) 
        *kid_len = len;

    return num;
}

static char * _fill_apu_from_sender(char *sender)
{
    char  *base64url_encode_buf = NULL;
    size_t base64url_encode_len;  

    if (NULL == sender)
        return NULL;

    base64url_encode_len = BASE64_ENCODE_GETLENGTH(strlen(sender));
    base64url_encode_buf = malloc(base64url_encode_len);
    if (NULL == base64url_encode_buf)
        return NULL;
    memset(base64url_encode_buf, 0, base64url_encode_len);
    base64url_encode(sender, strlen(sender), base64url_encode_buf, &base64url_encode_len);

    return base64url_encode_buf;      
}

static char * _fill_recipients_apv(char *recipients_kid[JOSE_JWE_RECIPIENTS_MAX])
{
    psa_status_t status;

    char *apv = NULL, *base64url_encode_buf = NULL;
    uint8_t hash[32]  = {0};
    size_t hash_length;
    size_t base64url_encode_len;    
    uint32_t recipients_kid_len = 0, idx = 0; 
    
    int recipients_num = _find_recipients_num(recipients_kid, (unsigned int *)&recipients_kid_len);
    if (0 == recipients_num)
        return NULL;        
        
    apv = malloc(recipients_kid_len + recipients_num);
    if (NULL == apv)
        return NULL;
    memset(apv, 0, recipients_kid_len + recipients_num);

    for (int i = 0; i < 4; i++) {
        if (recipients_kid[i]) {
            memcpy(&apv[idx], recipients_kid[i], strlen(recipients_kid[i]));
            recipients_num--;
            if (recipients_num) {
                idx += strlen(recipients_kid[i]);
                apv[idx++] = '.';
            }
        }
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)apv, strlen(apv), hash, 32, &hash_length);
    if (PSA_SUCCESS != status)
        goto exit;   

    base64url_encode_len = BASE64_ENCODE_GETLENGTH(hash_length);
    base64url_encode_buf = malloc(base64url_encode_len);
    if (NULL == base64url_encode_buf)
        goto exit;
    memset(base64url_encode_buf, 0, base64url_encode_len);
    base64url_encode((const char *)hash, hash_length, base64url_encode_buf, &base64url_encode_len);     

exit:
    if (apv)
        free(apv);

    return base64url_encode_buf;
}

static char * _jwe_protectedheader_serialize(JweProtectedHeader *protected, bool format)
{
    char *protected_serialize = NULL;

    if (NULL == protected)
        return NULL;

    cJSON *json_protected = cJSON_CreateObject();
    cJSON_AddStringToObject(json_protected, "typ", protected->typ);
    cJSON_AddStringToObject(json_protected, "alg", _jwe_kw_algorithm_as_str(protected->alg));
    cJSON_AddStringToObject(json_protected, "enc", _jwe_enc_algorithm_as_str(protected->enc));
    if (protected->skid)
        cJSON_AddStringToObject(json_protected, "skid", protected->skid);
    if (protected->apu)
        cJSON_AddStringToObject(json_protected, "apu", protected->apu);
    cJSON_AddStringToObject(json_protected, "apv", protected->apv);
    if (protected->epk)
        cJSON_AddItemToObject(json_protected, "epk", (cJSON *)protected->epk);

    if (format)
        protected_serialize = cJSON_Print(json_protected);
    else
        protected_serialize = cJSON_PrintUnformatted(json_protected);

    cJSON_Delete(json_protected);

    return protected_serialize;
}

char *iotex_jwe_encrypt_plaintext(psa_key_id_t key_id, char *plaintext, size_t pLen, char *nonce, size_t nonce_len, char *ad, size_t ad_len, size_t *ciphertext_length)
{
    psa_status_t status;
    
    if (NULL == plaintext || 0 == pLen) 
        return NULL;
    
    if (NULL == nonce || 0 == nonce_len)
        return NULL;
    
    if (NULL == ad || 0 == ad_len)
        return NULL;
    
    if (nonce_len != PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CCM))
        return NULL;
    
    char *ciphertext = malloc(pLen + PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_AES, 256, PSA_ALG_CCM));
    if (NULL == ciphertext) {
        return NULL; 
    }               
    
    status =  psa_aead_encrypt(key_id, PSA_ALG_CCM, (const uint8_t *)nonce, nonce_len, (const uint8_t *)ad, ad_len, (const uint8_t *)plaintext, pLen, (uint8_t *)ciphertext, pLen + PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_AES, 256, PSA_ALG_CCM), ciphertext_length);
    if (PSA_SUCCESS != status)
        return NULL;
    
    return ciphertext;         
}

char * iotex_jwe_decrypt_plaintext(psa_key_id_t key_id, char *ciphertext, size_t ciphertext_length, char *tag, size_t tag_length, char *nonce, size_t nonce_len, char *ad, size_t ad_len, size_t *plaintext_length)
{
    psa_status_t status;
    
    if (NULL == plaintext_length) 
        return NULL;
    
    if (NULL == nonce || 0 == nonce_len)
        return NULL;
    
    if (NULL == ad || 0 == ad_len)
        return NULL;
    
    if (nonce_len != PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CCM))
        return NULL;  
    
    size_t plaintext_size = PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE( ciphertext_length ) + 1;
    char *plaintext = malloc(plaintext_size);
    if (NULL == plaintext)
        return NULL; 
    memset(plaintext, 0, plaintext_size);
    
    char *ciphertext_tag = malloc(ciphertext_length + tag_length);
    if (NULL == ciphertext_tag) 
        goto exit;
    
    memset(ciphertext_tag, 0, ciphertext_length + tag_length);
    memcpy(ciphertext_tag, ciphertext, ciphertext_length);
    memcpy(ciphertext_tag + ciphertext_length, tag, tag_length);
    
    status = psa_aead_decrypt( key_id, PSA_ALG_CCM, (const uint8_t *)nonce, nonce_len, (const uint8_t *)ad, ad_len, (const uint8_t *)ciphertext_tag, ciphertext_length + tag_length, (uint8_t *)plaintext, plaintext_size, plaintext_length );
    if (PSA_SUCCESS == status) 
        goto exit2;

exit:
    if (plaintext) {
        free(plaintext);
        plaintext = NULL;
    }
exit2:
    if (ciphertext_tag)
        free(ciphertext_tag);


    return plaintext;
}


char *iotex_jwe_encrypt_protected(enum KWAlgorithms KwAlg, enum EncAlgorithm enAlg, char *sender, char *recipients_kid[4], JWK *epk)
{
    char *protected_base64 = NULL, *apv = NULL, *apu = NULL, *protected_json = NULL;
    
    if (NULL == epk)
        return NULL;
    
    apv = _fill_recipients_apv(recipients_kid);
    if (NULL == apv)
        return NULL;
    
    apu = _fill_apu_from_sender(sender);

    JweProtectedHeader protected;
    protected.typ = JOSE_HEADER_TYPE_ENCRPT_TYPE;
    protected.alg = KwAlg;
    protected.enc = enAlg;
    protected.skid = sender;
    protected.apu = apu;
    protected.apv = apv;
    protected.epk = _did_jwk_json_generate(epk);          

    protected_json = _jwe_protectedheader_serialize(&protected, false);
    
    if (protected_json)
        protected_base64 = base64_encode_automatic(protected_json, strlen(protected_json));
            
    if (apu)
        free(apu);

    if (apv)
        free(apv);

    if (protected_json)
        free(protected_json);

    return protected_base64;      
}

#if 0
char * iotex_jwe_encrypt(char *plaintext, enum KWAlgorithms alg, enum EncAlgorithm enc, char *sender, JWK *sJWK, char *recipients[JOSE_JWE_RECIPIENTS_MAX], bool format)
{
    psa_status_t status;
    uint8_t cekey[32] = {0}, nonce[13] = {0};;
    size_t clen = 0;
    JWK *epk = NULL;
    psa_key_id_t cekey_id, wrap_id, epk_id; 

    if (NULL == plaintext)
        return NULL;

    status = psa_generate_random( cekey, sizeof(cekey) );
    if (PSA_SUCCESS != status)
        return NULL;
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    if (enc == A256cbcHs512)
        psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    else if (enc == A256Gcm)
        psa_set_key_algorithm(&attributes, PSA_ALG_GCM);    
    else
        return NULL;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_bits(&attributes, 256); 
    
    status = psa_import_key( &attributes, cekey, 32, &cekey_id );
    if (PSA_SUCCESS != status)
        return NULL;          

    epk = iotex_jwk_generate_by_secret(cekey, sizeof(cekey), JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                                        PSA_KEY_LIFETIME_VOLATILE,
                                        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                                        PSA_ALG_ECDSA(PSA_ALG_SHA_256), &epk_id);
    if (NULL == epk)
        return NULL;                                            

    char *protected = iotex_jwe_encrypt_protected(alg, enc, sender, recipients, epk);
    if (NULL == protected)
        return NULL;

    int nonce_length = PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CCM);
    status =  psa_generate_random( nonce, nonce_length );
    if (PSA_SUCCESS != status)
        return NULL;          
  
    char *ciphertext = iotex_jwe_encrypt_plaintext(cekey_id, plaintext, strlen(plaintext), nonce, nonce_length, protected, strlen(protected), &clen);
    if (NULL == ciphertext)
        return NULL;

    char *cipher_base64url = base64_encode_automatic(ciphertext, strlen(plaintext));
    char *tag_base64url    = base64_encode_automatic(ciphertext + strlen(plaintext), clen - strlen(plaintext));
    char *iv_base64url     = base64_encode_automatic(nonce, nonce_length);

    uint8_t recipient_key[ 2*32 ] = {0}, secret[32] = {0};
    size_t secret_len = 0;

#include "include/backends/tinycryt/ecc.h"
#include "include/backends/tinycryt/ecc_dh.h"

	uint8_t private[32] = {0};
    if (!uECC_make_key(recipient_key, private, uECC_secp256r1()))
        return NULL;
    
    status = psa_raw_key_agreement(PSA_ALG_ECDH, 2, recipient_key, 64, secret, 32, &secret_len);
    if (PSA_SUCCESS != status)
        return NULL;   
    
    char *wkey = malloc(32 + 16);
    size_t wkey_len = 0;

    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    status = psa_import_key( &attributes, secret, 32, &wrap_id );  
    if (PSA_SUCCESS != status)
        return NULL;
    
    status = psa_cipher_encrypt(wrap_id, PSA_ALG_CBC_NO_PADDING, cekey, 32, wkey, 32 + 16, &wkey_len);
    if (PSA_SUCCESS != status)
        return NULL;
    
    char *wkey_base64url = base64_encode_automatic(wkey, 32 + 16);
    
    Recipient recipient;
    recipient.header.kid = recipients[0];
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

    return encrypt_str;
}
#else
char *iotex_jwe_encrypt(char *plaintext, enum KWAlgorithms alg, enum EncAlgorithm enc, char *sender, JWK *sJWK, char *recipients_kid[JOSE_JWE_RECIPIENTS_MAX], bool format)
{
    psa_status_t psa_status;
    uint8_t cek[32] = {0}, nonce[13] = {0};;
    psa_key_id_t cek_id = 0, wrap_id = 0, epk_id = 0;

    char *protected = NULL, *cipher_b64u = NULL, *tag_b64u = NULL, *iv_b64u = NULL, *encrypted_str = NULL;;

    Recipient recipients[JOSE_JWE_RECIPIENTS_MAX] = {0}; 

    if (NULL == plaintext)
        return NULL;
    
    psa_status = psa_generate_random( cek, sizeof(cek) );
    if (PSA_SUCCESS != psa_status)
        return NULL;
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    if (enc == A256cbcHs512)
        psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    else if (enc == A256Gcm)
        psa_set_key_algorithm(&attributes, PSA_ALG_GCM);    
    else
        return NULL;
    
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_bits(&attributes, 256); 
    
    psa_status = psa_import_key( &attributes, cek, sizeof(cek), &cek_id );
    if (PSA_SUCCESS != psa_status)
        return NULL;          
    
    JWK *epk = iotex_jwk_generate_by_secret(cek, sizeof(cek), JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                                        PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH, (unsigned int *)&epk_id);
    if (NULL == epk)
        goto exit;                                            
    
    protected = iotex_jwe_encrypt_protected(alg, enc, sender, recipients_kid, epk);
    if (NULL == protected)
        goto exit;
    
    int nonce_length = PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CCM);
    psa_status =  psa_generate_random( nonce, nonce_length );
    if (PSA_SUCCESS != psa_status)
        goto exit;          

    size_t ciphertext_len = 0;
    char *ciphertext = iotex_jwe_encrypt_plaintext(cek_id, plaintext, strlen(plaintext), (char *)nonce, nonce_length, protected, strlen(protected), &ciphertext_len);
    if (NULL == ciphertext)
        goto exit;
    
    cipher_b64u = base64_encode_automatic(ciphertext, strlen(plaintext));
    tag_b64u    = base64_encode_automatic(ciphertext + strlen(plaintext), ciphertext_len - strlen(plaintext));
    iv_b64u     = base64_encode_automatic((const char *)nonce, nonce_length);

    if (ciphertext) {
        free(ciphertext);
        ciphertext = NULL;
    }
    
    size_t  secret_len = 0, rkey_len = 0;
    char rkey[64] = {0}, secret[32] = {0};
    uint32_t recipients_success = 0;

    for (int i = 0; i < JOSE_JWE_RECIPIENTS_MAX; i ++) {

        if ( NULL == recipients_kid[i] )
            continue;

        jose_status_t jose_status = iotex_jwk_get_pubkey_from_jwk(iotex_registry_find_jwk_by_kid(recipients_kid[i]), rkey, &rkey_len);
        if (JOSE_SUCCESS != jose_status)
            continue;

        psa_status = psa_raw_key_agreement(PSA_ALG_ECDH, epk_id, (const uint8_t *)rkey, 64, (uint8_t *)secret, 32, &secret_len);
        if (PSA_SUCCESS != psa_status)
            continue;
    
        psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);

        psa_status = psa_import_key( &attributes, (const uint8_t *)secret, 32, &wrap_id );  
        if (PSA_SUCCESS != psa_status)
            continue;       
        
        uint8_t wkey[48] = {0};
        size_t  wkey_len = 0;

        psa_status = psa_cipher_encrypt(wrap_id, PSA_ALG_CBC_NO_PADDING, cek, 32, wkey, 48, &wkey_len);
        if (PSA_SUCCESS != psa_status) {
            if (wrap_id)
                psa_destroy_key(wrap_id);

            continue;
        }
         
        // char *wkey_base64url = base64_encode_automatic(wkey, 32 + 16);
            
        recipients[i].header.kid    = recipients_kid[i];
        recipients[i].encrypted_key = base64_encode_automatic((const char *)wkey, 32 + 16);

        recipients_success++;

        psa_destroy_key(wrap_id);
    }

    if (0 == recipients_success)
        goto exit;
    
    cJSON *recipient        = NULL;
    cJSON *recipient_header = NULL;
    cJSON *recipients_obj   = cJSON_CreateArray();

    for (int i = 0; i < JOSE_JWE_RECIPIENTS_MAX; i ++) {

        if (recipients[i].header.kid && recipients[i].encrypted_key) {
            recipient_header = cJSON_CreateObject();
            cJSON_AddStringToObject(recipient_header, "kid", recipients[i].header.kid);

            recipient = cJSON_CreateObject();
            cJSON_AddItemToObject(recipient, "header", recipient_header);
            cJSON_AddStringToObject(recipient, "encrypted_key", recipients[i].encrypted_key);

            cJSON_AddItemToArray(recipients_obj, recipient);

            free(recipients[i].encrypted_key);
        }
    }
   
    cJSON *encrypt_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(encrypt_obj, "ciphertext", cipher_b64u);
    cJSON_AddStringToObject(encrypt_obj, "protected", protected);
    cJSON_AddItemToObject(encrypt_obj,   "recipients", recipients_obj);
    cJSON_AddStringToObject(encrypt_obj, "tag", tag_b64u);
    cJSON_AddStringToObject(encrypt_obj, "iv", iv_b64u);

    if (format)
        encrypted_str = cJSON_Print(encrypt_obj);
    else
        encrypted_str = cJSON_PrintUnformatted(encrypt_obj);

    cJSON_Delete(encrypt_obj);        
    
exit:
    if (epk)
        iotex_jwk_destroy(epk);

    if (epk_id) 
        psa_destroy_key(epk_id);

    if (cek_id)        
        psa_destroy_key(cek_id);

    if (protected)        
        free(protected);

    if (cipher_b64u)
        free(cipher_b64u);

    if (tag_b64u)
        free(tag_b64u);

    if (iv_b64u)
        free(iv_b64u);                

    return encrypted_str;
}
#endif

char *iotex_jwe_decrypt(char *jwe_serialize, enum KWAlgorithms alg, enum EncAlgorithm enc, char *sender, JWK *sJWK, char *recipients_kid)
{
    char *plaintext = NULL;

    if (NULL == jwe_serialize)
        return NULL;

    cJSON *cipher_root = cJSON_Parse(jwe_serialize);            // Caution : delete cipher_root
    if (NULL == cipher_root)
        return NULL;

    cJSON *ciphertext_item = cJSON_GetObjectItem(cipher_root, "ciphertext");
    if (NULL == ciphertext_item)
        goto exit_1;

    size_t ciphertext_length = 0;
    char *ciphertext = base64_decode_automatic( ciphertext_item->valuestring, strlen(ciphertext_item->valuestring), &ciphertext_length);    // Caution : free ciphertext
    if (NULL == ciphertext)
        goto exit_1;

    cJSON *tag_item = cJSON_GetObjectItem(cipher_root, "tag");
    if (NULL == tag_item)
        goto exit_2;

    size_t tag_length = 0;
    char *tag = base64_decode_automatic( tag_item->valuestring, strlen(tag_item->valuestring), &tag_length);    // Caution : free tag
    if (NULL == tag)
        goto exit_2;   

    cJSON *iv_item = cJSON_GetObjectItem(cipher_root, "iv");
    if (NULL == iv_item)
        goto exit_3;

    size_t iv_length = 0;
    char *iv = base64_decode_automatic( iv_item->valuestring, strlen(iv_item->valuestring), &iv_length);        // Caution : free iv
    if (NULL == iv)
        goto exit_3;   

    cJSON *protected_item = cJSON_GetObjectItem(cipher_root, "protected");
    if (NULL == protected_item)
        goto exit_4;

    size_t protected_length = 0;
    char *protected = base64_decode_automatic( protected_item->valuestring, strlen(protected_item->valuestring), &protected_length);  // Caution : free protected
    if (NULL == protected)
        goto exit_4;    
               
    cJSON *protected_root = cJSON_Parse(protected);     // Caution : delete protected_root
    if (NULL == protected_root)
        goto exit_5;

    cJSON *epk_item = cJSON_GetObjectItem(protected_root, "epk");
    if (NULL == epk_item)
        goto exit_6;
        
    JWK *epk = iotex_jwk_get_jwk_from_json_value((void *)epk_item);         // Caution : destroy epk
    if (NULL == epk)
        goto exit_6;

    char epk_pub[64] = {0};
    size_t epk_pub_len = 0;
    jose_status_t status = iotex_jwk_get_pubkey_from_jwk(epk, epk_pub, &epk_pub_len);
    if (JOSE_SUCCESS != status)
        goto exit_7;
    
    cJSON *recipients_array = cJSON_GetObjectItem(cipher_root, "recipients");
    if (NULL == recipients_array)
        goto exit_7;

    cJSON *recipient_item = NULL, *recipient_header_item = NULL, *recipient_header_kid_item = NULL, *recipient_encrypted_key_item = NULL;
    int recipients_array_size = cJSON_GetArraySize(recipients_array); 
    for(int i = 0; i < recipients_array_size; i++) {

        recipient_item = cJSON_GetArrayItem(recipients_array, i);
        if (NULL == recipient_item)
            continue;

        recipient_header_item = cJSON_GetObjectItem(recipient_item, "header");
        if (NULL == recipient_header_item)
            continue;

        recipient_header_kid_item = cJSON_GetObjectItem(recipient_header_item, "kid");
        if (NULL == recipient_header_kid_item)
            continue;    

        if (0 == strcmp(recipient_header_kid_item->valuestring, recipients_kid)) {
            recipient_encrypted_key_item = cJSON_GetObjectItem(recipient_item, "encrypted_key");
            break;
        }         
    }

    if (NULL == recipient_encrypted_key_item)
        goto exit_7;

    size_t encrypted_key_len = 0;
    char *encrypted_key = base64_decode_automatic( recipient_encrypted_key_item->valuestring, strlen(recipient_encrypted_key_item->valuestring), &encrypted_key_len); // Caution : free encrypted_key   
    if (0 == encrypted_key_len)
        goto exit_7;

    psa_key_id_t key_id = iotex_jwk_get_psa_key_id_from_didurl(recipients_kid);
    if (0 == key_id)
        goto exit_8;
    
    size_t  secret_len = 0;
    uint8_t secret[32] = {0};    
    psa_status_t psa_status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id, (const uint8_t *)epk_pub, 64, secret, 32, &secret_len);
    if (PSA_SUCCESS != psa_status)
        goto exit_8;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);  
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_bits(&attributes, 256); 

    psa_key_id_t psa_keyid;
    psa_status = psa_import_key( &attributes, secret, 32, &psa_keyid );  
    if (PSA_SUCCESS != psa_status)
        goto exit_8;

    uint8_t cek[32] = {0};
    size_t cek_len = 0;
    psa_status = psa_cipher_decrypt( psa_keyid, PSA_ALG_CBC_NO_PADDING, (const uint8_t *)encrypted_key, encrypted_key_len, cek, sizeof(cek), &cek_len );
    psa_destroy_key(psa_keyid);    
    if (PSA_SUCCESS != psa_status) 
        goto exit_8;

    if (enc == A256cbcHs512)
        psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    else if (enc == A256Gcm)
        psa_set_key_algorithm(&attributes, PSA_ALG_GCM);    
    else
        goto exit_8;   

    psa_status = psa_import_key( &attributes, cek, sizeof(cek), &psa_keyid );
    if (PSA_SUCCESS != psa_status)
        goto exit_8; 

    size_t plaintext_length = 0;  
    plaintext = iotex_jwe_decrypt_plaintext(psa_keyid, ciphertext, ciphertext_length, tag, tag_length, iv, iv_length, protected_item->valuestring, strlen(protected_item->valuestring), &plaintext_length);

    psa_destroy_key(psa_keyid);

exit_8:
    if (encrypted_key)
        free(encrypted_key);
exit_7:
    if (epk)
        iotex_jwk_destroy(epk);
exit_6:
    if (protected_root)
        cJSON_Delete(protected_root);
exit_5:
    if (protected)
        free(protected);
exit_4:
    if (iv)
        free(iv);
exit_3:
    if (tag)
        free(tag);
exit_2:
    if (ciphertext)
        free(ciphertext);
exit_1:
    if (cipher_root)
        cJSON_Delete(cipher_root);

    return plaintext;    
}

