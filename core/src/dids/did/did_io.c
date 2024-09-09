#include <stdlib.h>
#include <string.h>

#include "include/server/crypto.h"
#include "include/jose/jwk.h"
#include "include/dids/did/did.h"
#include "include/dids/did/did_io.h"
#include "include/utils/cJSON/cJSON.h"
#include "include/utils/keccak256/keccak256.h"

static char *name(void)
{
    return DID_METHOD_IO_NAME;
}

static char *generate(JWK *jwk)
{
    char public_key[64]   = {0};
    // char internal_raw[36] = {0};
    // char *coverted = NULL, *did_str = NULL; 
    char *did_str = NULL;

    if ( NULL == jwk )
        return NULL;

    if (jwk->type == JWKTYPE_EC) {
        if (0 == strcmp(jwk->Params.ec.crv, "secp256k1") || 0 == strcmp(jwk->Params.ec.crv, "P-256")) {
           
            size_t outlen = 0;
            
            jose_status_t status = iotex_jwk_get_pubkey_from_jwk(jwk, public_key, &outlen);
            if (JOSE_SUCCESS != status)
                return NULL;

            did_str = calloc(strlen("did:io:") + 2 + 20 * 2 + 1, sizeof(char));                

            uint8_t hash[32] = {0};
            keccak256_getHash((const uint8_t *)public_key, 64, hash);

            strcpy(did_str, "did:io:");

            int idx = strlen("did:io:");                 
            did_str[idx++] = '0';
            did_str[idx++] = 'x';

            for (int i = 0; i < 20; i++) {
                char buf[3] = {0};
                sprintf(buf, "%02x", hash[32 - 20 + i]);

                memcpy(did_str + idx + i * 2, buf, 2);
            }            
            
            return did_str;
        }
    }

    return NULL;
}

DID_Method did_io_method = {name, generate, NULL, NULL, NULL, NULL, NULL, NULL, NULL};