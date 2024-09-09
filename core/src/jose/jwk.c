#include <stdlib.h>
#include <string.h>

#include "include/server/crypto.h"

#include "include/jose/jwk.h"
#include "include/dids/did/did.h"
#include "include/dids/did/registry.h"
#include "include/utils/cJSON/cJSON.h"
#include "include/utils/baseX/base64.h"

enum JWAlogrithm iotex_jwk_get_algorithm(JWK *jwk)
{
    if (NULL == jwk)
        return None;

    switch (jwk->type)
    {
    case JWKTYPE_EC:
        if (0 == strcmp(jwk->Params.ec.crv, "P-256"))
            return ES256;

        if (0 == strcmp(jwk->Params.ec.crv, "secp256k1"))
            return ES256K;    
        break;
    case JWKTYPE_Symmetric:
        break;
    case JWKTYPE_RSA:
        break;
    case JWKTYPE_OKP:
        if (0 == strcmp(jwk->Params.okp.crv, "Ed25519"))
            return EdDSA;   
        break;        
    default:
        break;
    }        

    return None;
}

enum KnownKeyAlg iotex_jwk_get_key_alg(JWK *jwk)
{
    if (NULL == jwk)
        return None;
    
    switch (jwk->type)
    {
    case JWKTYPE_EC:
    
        if (0 == strcmp(jwk->Params.ec.crv, "P-256"))
            return P256;

        if (0 == strcmp(jwk->Params.ec.crv, "secp256k1"))
            return K256;    
        break;
    case JWKTYPE_Symmetric:
        break;
    case JWKTYPE_RSA:
        break;
    case JWKTYPE_OKP:
        if (0 == strcmp(jwk->Params.okp.crv, "Ed25519"))
            return Ed25519;   
        break;        
    default:
        break;
    }        

    return Unsupported;
}

JWK *iotex_jwk_get_jwk_from_json_value(void *json_value)
{
    if (NULL == json_value)
        return NULL;
    
    cJSON *jwk_item = (cJSON *)json_value;
    if (!cJSON_IsObject(jwk_item))
        return NULL;

    JWK *jwk = malloc(sizeof(JWK));
    if (NULL == jwk)
        return NULL;
    memset(jwk, 0, sizeof(JWK));

    cJSON *type_item = cJSON_GetObjectItem(jwk_item, "kty");
    if (NULL == type_item)
        goto exit;
    
    if (0 == strcmp(type_item->valuestring, "EC"))
        jwk->type = JWKTYPE_EC;
    else 
        goto exit;
    
    cJSON *kid_item = cJSON_GetObjectItem(jwk_item, "kid");
    if (NULL == kid_item)
        goto exit;

    jwk->key_id = iotex_jwk_get_psa_key_id_from_didurl(kid_item->valuestring);
    if (0 == jwk->key_id)
        goto exit;
    
    if (jwk->type == JWKTYPE_EC) {

        cJSON *crv_item = cJSON_GetObjectItem(jwk_item, "crv");
        if (NULL == crv_item)
            goto exit;

        strcpy(jwk->Params.ec.crv, crv_item->valuestring);

        cJSON *x_item = cJSON_GetObjectItem(jwk_item, "x");
        if (NULL == x_item)
            goto exit;

        strcpy(jwk->Params.ec.x_coordinate, x_item->valuestring);

        cJSON *y_item = cJSON_GetObjectItem(jwk_item, "y");
        if (NULL == y_item)
            goto exit;

        strcpy(jwk->Params.ec.y_coordinate, y_item->valuestring);  

        cJSON *d_item = cJSON_GetObjectItem(jwk_item, "d");
        if (NULL != d_item)
            strcpy(jwk->Params.ec.ecc_private_key, d_item->valuestring);           
    
        return jwk;
    }

exit:

    if (jwk)
        iotex_jwk_destroy(jwk);

    return NULL;
}

JWK *iotex_jwk_copy(JWK *jwk, bool skipPrivate)
{
    JWK *jwk_new = NULL;

    if (NULL == jwk)
        return NULL;

    switch (jwk->type) {
        case JWKTYPE_EC:
            jwk_new = malloc(sizeof(JWK));
            if (NULL == jwk_new)
                return NULL;

            memcpy(jwk_new, jwk, sizeof(JWK));

            if (jwk->x509_url)
                jwk_new->x509_url = strdup(jwk->x509_url);

            if (jwk->x509_certificate_chain)
                jwk_new->x509_certificate_chain = strdup(jwk->x509_certificate_chain);

            if (skipPrivate)   
                memset(jwk_new->Params.ec.ecc_private_key, 0, sizeof(jwk_new->Params.ec.ecc_private_key));

            return jwk_new;
        case JWKTYPE_Symmetric:
            break;
        case JWKTYPE_RSA:
            break;
        case JWKTYPE_OKP:
            break;        
        default:
            break;
    }

    return NULL;      
}

JWK *iotex_jwk_to_public(JWK *jwk)
{
    return iotex_jwk_copy(jwk, true);
}

bool iotex_jwk_equals(JWK *jwk1, JWK *jwk2, bool skipPri)
{
    if (NULL == jwk1 || NULL == jwk2)
        return false;

    if (jwk1->type != jwk2->type)
        return false;

    switch (jwk1->type) {
        case JWKTYPE_EC:

            if (0 != strcmp(jwk1->Params.ec.crv, jwk2->Params.ec.crv))
                return false;

            if (0 != strcmp(jwk1->Params.ec.x_coordinate, jwk2->Params.ec.x_coordinate))
                return false;

            if (0 != strcmp(jwk1->Params.ec.y_coordinate, jwk2->Params.ec.y_coordinate))
                return false;

            if (skipPri)
                return true;

            if (0 != strcmp(jwk1->Params.ec.ecc_private_key, jwk2->Params.ec.ecc_private_key))
                return false;

            return true;
        case JWKTYPE_Symmetric:
            break;
        case JWKTYPE_RSA:
            break;
        case JWKTYPE_OKP:
            break;        
        default:
            break;
    }

    return false;    
}

void *_did_jwk_json_generate(JWK *jwk)
{
    char fragment[32] = {0};

    if (NULL == jwk)
        return NULL;

    if (0 == jwk->key_id) 
        return NULL;

    cJSON *JWK_object = cJSON_CreateObject();  
    switch (jwk->type) {
        case JWKTYPE_EC:
            if (jwk->Params.ec.crv[0])
                cJSON_AddStringToObject(JWK_object, "crv", (const char *)(jwk->Params.ec.crv));
            else
                goto exit;

            if (jwk->Params.ec.x_coordinate[0]) 
                cJSON_AddStringToObject(JWK_object, "x", (const char *)jwk->Params.ec.x_coordinate);
            else
                goto exit;

            if (jwk->Params.ec.y_coordinate[0])
                cJSON_AddStringToObject(JWK_object, "y", (const char *)jwk->Params.ec.y_coordinate);
            else
                goto exit;

            if (jwk->Params.ec.ecc_private_key[0]) {
                cJSON_AddStringToObject(JWK_object, "d", (const char *)jwk->Params.ec.ecc_private_key);
            }

            cJSON_AddStringToObject(JWK_object, "kty", "EC");

            if (0 == strcmp(jwk->Params.ec.crv, "P-256"))
                sprintf(fragment, "Key-p256-%d", jwk->key_id);
            else
                sprintf(fragment, "Key-%s-%d",jwk->Params.ec.crv, jwk->key_id);

            break;
        case JWKTYPE_Symmetric:
            cJSON_AddStringToObject(JWK_object, "kty", "OCT");
            break;
        case JWKTYPE_RSA:
            cJSON_AddStringToObject(JWK_object, "kty", "RSA");
            break;
        case JWKTYPE_OKP:
            cJSON_AddStringToObject(JWK_object, "kty", "OCT");
            break;        
        default:
            goto exit;
    }
   
    cJSON_AddStringToObject(JWK_object, "kid", fragment);


    return (void *)JWK_object;

exit:
    cJSON_Delete(JWK_object);

    return NULL;
}

char *iotex_jwk_serialize(JWK *jwk, bool format)
{
    char *toStr = NULL;

    if (NULL == jwk)
        return NULL;

    cJSON *JWK_object = _did_jwk_json_generate(jwk);
    if (NULL == JWK_object)
        return NULL;
        
    if (format)
        toStr = cJSON_Print(JWK_object);
    else
        toStr = cJSON_PrintUnformatted(JWK_object);

    cJSON_Delete(JWK_object);

    return toStr;
}

char *iotex_jwk_generate_kid(char *method, JWK *jwk)
{
    char fragment[32] = {0};

    if (NULL == jwk)
        return NULL;

    if (NULL == method)
        return NULL;
    
    char *did = iotex_did_generate(method, jwk);
    if (NULL == did)
        return NULL;
    
    switch (jwk->type) {
        case JWKTYPE_EC:
    
            if (jwk->Params.ec.crv[0]) {
                if (0 == strcmp(jwk->Params.ec.crv, "P-256"))
                    sprintf(fragment, "#Key-p256-%d", jwk->key_id);
                else
                    sprintf(fragment, "#Key-%s-%d",jwk->Params.ec.crv, jwk->key_id);
            } else
                sprintf(fragment, "#key-%d", jwk->key_id);
    
            break;
        default:
            return NULL;
    }
    
    char *kid = calloc(strlen(did) + strlen(fragment) + 1, sizeof(char));
    if (NULL == kid)
        return NULL;
    
    kid =  strcat(strcat(kid, did), fragment);

    free(did);

    return kid;
}

void iotex_jwk_destroy(JWK *jwk)
{
    if (NULL == jwk)
        return;

    if (jwk->x509_url) 
        free(jwk->x509_url);

    if (jwk->x509_certificate_chain) 
        free(jwk->x509_certificate_chain);

    memset(jwk->x509_thumbprint_sha1,   0, sizeof(jwk->x509_thumbprint_sha1));
    memset(jwk->x509_thumbprint_sha256, 0, sizeof(jwk->x509_thumbprint_sha256));

    memset(&jwk->Params, 0, sizeof(jwk->Params));

    psa_destroy_key(jwk->key_id);

    free(jwk);  
}

jose_status_t iotex_pubkey_uncompress_convert_compress(const char *uncompress, char *compress)
{
    if (NULL == uncompress || NULL == compress)
        return JOSE_ERROR_INVALID_ARGUMENT;

    memcpy(compress + 1,  uncompress + 1, 32);

    if (uncompress[65] & 0x01) {
        compress[0] = 0x02;
    } else 
        compress[0] = 0x03;
    
    return JOSE_SUCCESS;
}

jose_status_t iotex_jwk_get_pubkey_from_jwk(JWK *jwk, char *outdata, size_t *outdata_len)
{
    size_t x_outlen = 0, y_outlen = 0;;

    if (NULL == jwk || NULL == outdata || NULL == outdata_len)
        return JOSE_ERROR_INVALID_ARGUMENT;

    switch (jwk->type) {
        case JWKTYPE_EC:
        
            base64url_decode(jwk->Params.ec.x_coordinate, strlen(jwk->Params.ec.x_coordinate), outdata, &x_outlen);
            base64url_decode(jwk->Params.ec.y_coordinate, strlen(jwk->Params.ec.y_coordinate), outdata + 32, &y_outlen);
        
            *outdata_len = x_outlen + y_outlen;

            return JOSE_SUCCESS;
    
        default:
            return JOSE_ERROR_NOT_SUPPORTED;
    }

    return JOSE_ERROR_GENERIC_ERROR;
}

static jose_status_t _jwk_psa_key_attributes_set(psa_key_attributes_t *attributes, enum JWKSupportKeyAlg keyalg, int lifetime, unsigned int key_usage, unsigned int alg, unsigned int key_id)
{
    if (NULL == attributes)
        return JOSE_ERROR_INVALID_ARGUMENT;

    psa_set_key_usage_flags(attributes, key_usage);
    psa_set_key_algorithm(attributes, alg);

    if (JWK_SUPPORT_KEY_ALG_P256 == keyalg) {
        psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(attributes, 256); 
    } else if (JWK_SUPPORT_KEY_ALG_K256 == keyalg) {
        psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
        psa_set_key_bits(attributes, 256); 
    } else if ((JWK_SUPPORT_KEY_ALG_ED25519 == keyalg)) {
        psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
        psa_set_key_bits(attributes, 512); 
    }

    psa_set_key_lifetime(attributes, lifetime);

    if (IOTEX_JWK_LIFETIME_PERSISTENT == lifetime)
        psa_set_key_id(attributes, key_id); 

    return JOSE_SUCCESS;         
}

JWK *iotex_jwk_generate(enum JWKType type, enum JWKSupportKeyAlg keyalg,
                                int lifetime, unsigned int key_usage, unsigned int alg, unsigned int *key_id)
{
    char exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)];
    size_t exported_length = 0;
    JWK *jwk = NULL;
    
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    
    if (type != JWKTYPE_EC)
        return NULL;
    
    if (IOTEX_JWK_LIFETIME_VOLATILE != lifetime && IOTEX_JWK_LIFETIME_PERSISTENT != lifetime)
        return NULL;
    
    if (NULL == key_id)        
        return NULL;
    
    if (IOTEX_JWK_LIFETIME_PERSISTENT == lifetime) {
        status = psa_export_public_key( (psa_key_id_t)*key_id, (uint8_t *)exported, sizeof(exported), &exported_length );
        if (PSA_SUCCESS == status)
            goto jwk_generater;
    }

    _jwk_psa_key_attributes_set(&attributes, keyalg, lifetime, key_usage, alg, *key_id);
    
    status = psa_generate_key(&attributes, (psa_key_id_t *)key_id);
    if( status != PSA_SUCCESS )
        return NULL;

    psa_export_public_key( *key_id, (uint8_t *)exported, sizeof(exported), &exported_length );

jwk_generater:

    jwk = malloc(sizeof(JWK));
    if (NULL == jwk)
        return NULL;
    memset(jwk, 0, sizeof(JWK));

    size_t x_len, y_len;
    base64url_encode((char *)exported, 32, jwk->Params.ec.x_coordinate, &x_len);
    base64url_encode((char *)exported + 32, 32, jwk->Params.ec.y_coordinate, &y_len);

    jwk->type = JWKTYPE_EC;
    if (JWK_SUPPORT_KEY_ALG_P256 == keyalg) {        
        // strncpy(jwk->Params.ec.crv, "P-256", strlen("P-256"));
        strcpy(jwk->Params.ec.crv, "P-256");
    } else if (JWK_SUPPORT_KEY_ALG_K256 == keyalg) {
        // strncpy(jwk->Params.ec.crv, "secp256k1", strlen("secp256k1"));
        strcpy(jwk->Params.ec.crv, "secp256k1");
    } else if ((JWK_SUPPORT_KEY_ALG_ED25519 == keyalg)) {
        // strncpy(jwk->Params.ec.crv, "Ed25519", strlen("Ed25519"));
        strcpy(jwk->Params.ec.crv, "Ed25519");
    }    

    jwk->key_id = *key_id;

    return jwk;
}

JWK* iotex_jwk_generate_by_secret(uint8_t *secret, unsigned int secret_size,
                                enum JWKType type, enum JWKSupportKeyAlg keyalg,
                                int lifetime, unsigned int key_usage, unsigned int alg, unsigned int *key_id)
{
    char exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)];
    size_t exported_length = 0;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    
    if (type != JWKTYPE_EC)
        return NULL;
    
    if (NULL == secret || 0 == secret_size)
        return NULL;
    
    if (secret_size != 32)        
        return NULL;
    
    if (IOTEX_JWK_LIFETIME_VOLATILE != lifetime && IOTEX_JWK_LIFETIME_PERSISTENT != lifetime)
        return NULL;
    
    if (NULL == key_id)        
        return NULL;
    
#if 0
    psa_set_key_usage_flags(&attributes, key_usage);
    psa_set_key_algorithm(&attributes, alg);

    if (JWK_SUPPORT_KEY_ALG_P256 == keyalg) {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, 256); 
    } else if (JWK_SUPPORT_KEY_ALG_K256 == keyalg) {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
        psa_set_key_bits(&attributes, 256); 
    } else if ((JWK_SUPPORT_KEY_ALG_ED25519 == keyalg)) {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
        psa_set_key_bits(&attributes, 512); 
    }

    psa_set_key_lifetime(&attributes, lifetime);

    if (IOTEX_JWK_LIFETIME_PERSISTENT == lifetime)
        psa_set_key_id(&attributes, *key_id);        
#else
    _jwk_psa_key_attributes_set(&attributes, keyalg, lifetime, key_usage, alg, *key_id);
#endif

    status = psa_import_key( &attributes, secret, 32, (psa_key_id_t *)key_id );
    if( status != PSA_SUCCESS )
        return NULL;
    
    status = psa_export_public_key( *key_id, (uint8_t *)exported, sizeof(exported), &exported_length );   
    if( status != PSA_SUCCESS )
        return NULL;

    JWK *jwk = malloc(sizeof(JWK));
    if (NULL == jwk)
        return NULL;        
    memset(jwk, 0, sizeof(JWK));        

    size_t x_len, y_len;
    base64url_encode((char *)exported, 32, jwk->Params.ec.x_coordinate, &x_len);
    base64url_encode((char *)exported + 32, 32, jwk->Params.ec.y_coordinate, &y_len);  

    jwk->type = JWKTYPE_EC;
    if (JWK_SUPPORT_KEY_ALG_P256 == keyalg) {
#if 0        
        strncpy(jwk->Params.ec.crv, "P-256", strlen("P-256"));
#else        
        strcpy(jwk->Params.ec.crv, "P-256");
#endif        
    } else if (JWK_SUPPORT_KEY_ALG_K256 == keyalg) {
#if 0        
        strncpy(jwk->Params.ec.crv, "secp256k1", strlen("secp256k1"));
#else
        strcpy(jwk->Params.ec.crv, "secp256k1");
#endif        
    } else if ((JWK_SUPPORT_KEY_ALG_ED25519 == keyalg)) {
#if 0        
        strncpy(jwk->Params.ec.crv, "Ed25519", strlen("Ed25519"));
#else
        strcpy(jwk->Params.ec.crv, "Ed25519");
#endif        
    }    

    jwk->key_id = *key_id;

    return jwk;
}

psa_key_id_t iotex_jwk_get_psa_key_id_from_didurl(char *didurl)
{
    psa_key_id_t key_id = 0;

    if (NULL == didurl)
        return key_id;

    int i = strlen(didurl) - 1;

    for (; i > 0; --i) {
        if (didurl[i] == '-')
            break;
    }

    if (i)
        key_id = atoi(didurl + i + 1);

    return key_id;
}



