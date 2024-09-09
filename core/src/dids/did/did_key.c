#include <stdlib.h>
#include <string.h>

#include "include/server/crypto.h"
#include "include/jose/jwk.h"
#include "include/dids/did/did.h"
#include "include/dids/did/did_key.h"
#include "include/utils/cJSON/cJSON.h"
#include "include/utils/baseX/base58.h"

static char did_str[128] = {0};

static char *name(void)
{
    return DID_METHOD_KEY_NAME;
}

static char *generate(JWK *jwk)
{
    char internal_uncompress[65] = {0};
    char internal_raw[36] = {0};
    char *coverted = NULL; 

    if ( NULL == jwk )
        return NULL;

    if (jwk->type == JWKTYPE_EC) {
        if (0 == strcmp(jwk->Params.ec.crv, "secp256k1") || 0 == strcmp(jwk->Params.ec.crv, "P-256")) {

            internal_raw[0] = 231;
            internal_raw[1] = 1;
            
            size_t outlen = 0;
            
            internal_uncompress[0] = 0x04;
            jose_status_t status = iotex_jwk_get_pubkey_from_jwk(jwk, internal_uncompress + 1, &outlen);
            if (JOSE_SUCCESS != status)
                return NULL;
            status = iotex_pubkey_uncompress_convert_compress(internal_uncompress, internal_raw + 2);
            if (JOSE_SUCCESS != status)
                return NULL;
            
            strcpy(did_str, "did:key:");
            coverted = base58_encode((const unsigned char *)internal_raw, 33 + 2);
            if (coverted) {
                
                strcpy(did_str + strlen("did:key:"), coverted);
                free(coverted);

                return did_str;
            }
        }
    }

    return NULL;
}

DID_Method did_key_method = {name, generate, NULL, NULL, NULL, NULL, NULL, NULL, NULL};