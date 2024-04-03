#include <stdlib.h>
#include <string.h>

#include "include/psa/crypto.h"

#include "include/jose/jwk.h"
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

JWK *iotex_jwk_to_public(JWK *jwk)
{
    JWK *jwk_public = NULL;

    if (NULL == jwk)
        return NULL;

    switch (jwk->type) {
        case JWKTYPE_EC:
            if (jwk->Params.ec.ecc_private_key[0]) {

                jwk_public = malloc(sizeof(JWK));
                if (NULL == jwk_public)
                    return NULL;

                memcpy(jwk_public, jwk, sizeof(JWK));   
                memset(jwk_public->Params.ec.ecc_private_key, 0, sizeof(jwk_public->Params.ec.ecc_private_key));

                return jwk_public;
            } 

            return jwk;
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
    if (NULL == jwk)
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
            break;
    }

    if (jwk->key_id) {
        char kid_str[32] = {0};
        sprintf(kid_str, "Key-%d", jwk->key_id);
        cJSON_AddStringToObject(JWK_object, "kid", kid_str);
    }    

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

    memset((void *)&jwk->Params, 0, sizeof(jwk->Params));

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

jose_status_t iotex_jwk_get_pubkey_from_jwk(JWK *jwk, char *outdata, uint32_t *outdata_len)
{
    int x_outlen = 0, y_outlen = 0;;

    if (NULL == jwk || NULL == outdata || NULL == outdata_len)
        return JOSE_ERROR_INVALID_ARGUMENT;

    switch (jwk->type) {
        case JWKTYPE_EC:
        
            outdata[0] = 0x04;
            base64url_decode(jwk->Params.ec.x_coordinate, strlen(jwk->Params.ec.x_coordinate), outdata + 1, &x_outlen);
            base64url_decode(jwk->Params.ec.y_coordinate, strlen(jwk->Params.ec.y_coordinate), outdata + 1 + 32, &y_outlen);
        
            *outdata_len = x_outlen + y_outlen + 1;

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
    
    status = psa_generate_key(&attributes, key_id);
    if( status != PSA_SUCCESS )
        return NULL;

    psa_export_public_key( *key_id, (uint8_t *)exported, sizeof(exported), &exported_length );

jwk_generater:

    jwk = malloc(sizeof(JWK));
    if (NULL == jwk)
        return NULL;
    memset(jwk, 0, sizeof(JWK));

    int x_len, y_len;
    base64url_encode((char *)exported, 32, jwk->Params.ec.x_coordinate, &x_len);
    base64url_encode((char *)exported + 32, 32, jwk->Params.ec.y_coordinate, &y_len);

    jwk->type = JWKTYPE_EC;
    if (JWK_SUPPORT_KEY_ALG_P256 == keyalg) {
        strncpy(jwk->Params.ec.crv, "P-256", strlen("P-256"));
    } else if (JWK_SUPPORT_KEY_ALG_K256 == keyalg) {
        strncpy(jwk->Params.ec.crv, "secp256k1", strlen("secp256k1"));
    } else if ((JWK_SUPPORT_KEY_ALG_ED25519 == keyalg)) {
        strncpy(jwk->Params.ec.crv, "Ed25519", strlen("Ed25519"));
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

    status = psa_import_key( &attributes, secret, 32, key_id );
    if( status != PSA_SUCCESS )
        return NULL;
    
    status = psa_export_public_key( *key_id, (uint8_t *)exported, sizeof(exported), &exported_length );   
    if( status != PSA_SUCCESS )
        return NULL;

    JWK *jwk = malloc(sizeof(JWK));
    if (NULL == jwk)
        return NULL;        
    memset(jwk, 0, sizeof(JWK));        

    int x_len, y_len;
    base64url_encode((char *)exported, 32, jwk->Params.ec.x_coordinate, &x_len);
    base64url_encode((char *)exported + 32, 32, jwk->Params.ec.y_coordinate, &y_len);  

    jwk->type = JWKTYPE_EC;
    if (JWK_SUPPORT_KEY_ALG_P256 == keyalg) {
        strncpy(jwk->Params.ec.crv, "P-256", strlen("P-256"));
    } else if (JWK_SUPPORT_KEY_ALG_K256 == keyalg) {
        strncpy(jwk->Params.ec.crv, "secp256k1", strlen("secp256k1"));
    } else if ((JWK_SUPPORT_KEY_ALG_ED25519 == keyalg)) {
        strncpy(jwk->Params.ec.crv, "Ed25519", strlen("Ed25519"));
    }    

    jwk->key_id = *key_id;

    return jwk;
}

