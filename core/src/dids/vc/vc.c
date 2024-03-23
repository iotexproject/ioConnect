#include <stdlib.h>
#include <stddef.h>
#include "include/dids/vc/vc.h"
#include "include/utils/cJSON/cJSON.h"

static Credential credentials[DID_VC_NUM_MAX] = {0};

VCHandle iotex_vc_new(void)
{
    for (int i = 0; i < DID_VC_NUM_MAX; i++) {
        if (0 == credentials[i].Contexts.num) {
            credentials[i].Contexts.context[0] = IOTEX_CREDENTIALS_V1_CONTEXT;
            credentials[i].Contexts.num = 1;
            return i;
        }
    }

    return -1;
}

int iotex_vc_add_context(VCHandle handle, char *context)
{
    if (NULL == context)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].Contexts.num >= DID_VC_CONTEXT_NUM_MAX)
        return -2;

    credentials[handle].Contexts.context[credentials[handle].Contexts.num] = context;
    credentials[handle].Contexts.num++;

    return 0;
}

int iotex_vc_add_id(VCHandle handle, char *id)
{
    if (NULL == id)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].id)
        return -2;

    credentials[handle].id = id;

    return 0;

}

int iotex_vc_update_id(VCHandle handle, char *id, int isfree)
{
    if (NULL == id)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].id && isfree)
        free(credentials[handle].id);

    credentials[handle].id = id;

    return 0;

}

int iotex_vc_add_type(VCHandle handle, char *type)
{
    if (NULL == type)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].types.num >= DID_VC_TYPE_NUM_MAX)
        return -2;

    credentials[handle].types.type[credentials[handle].types.num] = type;
    credentials[handle].types.num++;

    return 0;
}

int iotex_vc_add_issuer(VCHandle handle, char *issuer)
{
    if (NULL == issuer)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].issuer.id)
        return -2;

    credentials[handle].issuer.id = issuer;

    return 0;

}

int iotex_vc_update_issuer(VCHandle handle, char *issuer, int isfree)
{
    if (NULL == issuer)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].issuer.id && isfree)
        free(credentials[handle].issuer.id);

    credentials[handle].issuer.id = issuer;

    return 0;

}

int iotex_vc_add_issuance_date(VCHandle handle, char *issuance_date)
{
    if (NULL == issuance_date)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].issuance_date)
        return -2;

    credentials[handle].issuance_date = issuance_date;

    return 0;

}

int iotex_vc_update_issuance_date(VCHandle handle, char *issuance_date, int isfree)
{
    if (NULL == issuance_date)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].issuance_date && isfree)
        free(credentials[handle].issuance_date);

    credentials[handle].issuance_date = issuance_date;

    return 0;

}

int iotex_vc_add_credential_subjects(VCHandle handle, char *id)
{
    if (NULL == id)
        return -1;

    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].credential_subjects.num >= DID_VC_CREDENTIALSUBJECT_NUM_MAX)
        return -2;

    credentials[handle].credential_subjects.vc[credentials[handle].credential_subjects.num].id = id;
    credentials[handle].credential_subjects.num++;

    return 0;
}

static did_vc_proof_destroy(VC_Proof *proof)
{
    if (NULL == proof)
        return -1;

    if (proof->context)
        free(proof->context);

    if (proof->proof_value)
        free(proof->proof_value);

    if (proof->challenge)
        free(proof->challenge);

    if (proof->creator)
        free(proof->creator);

    if (proof->verification_method)
        free(proof->verification_method);

    if (proof->created)
        free(proof->created);

    if (proof->domain)
        free(proof->domain);

    if (proof->nonce)
        free(proof->nonce);

    if (proof->jws)
        free(proof->jws);        

    memset(proof, 0, sizeof(VC_Proof));
}

static void did_vc_status_destroy(VC_Status *status)
{
    if (NULL == status)
        return -1;

    if (status->id) {
        free(status->id);
        status->id = NULL;
    }

    if (status->type) {
        free(status->type);
        status->type = NULL;
    }
}

static void did_vc_termofuse_destroy(VC_TermOfUse *termofuse)
{
    if (NULL == termofuse)
        return -1;

    if (termofuse->id) {
        free(termofuse->id);
        termofuse->id = NULL;
    }

    if (termofuse->type) {
        free(termofuse->type);
        termofuse->type = NULL;
    }
}

static void did_vc_types_destroy(VC_Types *types)
{
    if (NULL == types)
        return -1;

    if (types->num) {
        for (int i = 0; i < DID_VC_TYPE_NUM_MAX; i++) {
            if (types->type[i]) {
                free(types->type[i]);
                types->type[i] = NULL;
            }
        }
    }
}

static void did_vc_evidence_destroy(VC_Evidence *evidence)
{
    if (NULL == evidence)
        return -1;

    if (evidence->id) {
        free(evidence->id);
        evidence->id = NULL;
    }

    did_vc_types_destroy(&evidence->types);
}

static void did_vc_schema_destroy(VC_Schema *schema)
{
    if (NULL == schema)
        return -1;

    if (schema->id) {
        free(schema->id);
        schema->id = NULL;
    }

   if (schema->type) {
        free(schema->type);
        schema->type = NULL;
   }
}

void iotex_vc_destroy(VCHandle handle)
{
    if (handle >= DID_VC_NUM_MAX)
        return -1;

    if (credentials[handle].Contexts.num) {
        for (int i = 0; i < DID_VC_CONTEXT_NUM_MAX; i++) {
            if (credentials[handle].Contexts.context[i]) {
                free(credentials[handle].Contexts.context[i]);
                credentials[handle].Contexts.context[i] = NULL;
            }
        }

        credentials[handle].Contexts.num = 0;
    }
    
    if (credentials[handle].id) {
        free(credentials[handle].id);
        credentials[handle].id = NULL;
    }

    if (credentials[handle].types.num) {
        for (int i = 0; i < DID_VC_TYPE_NUM_MAX; i++) {
            if (credentials[handle].types.type[i]) {
                free(credentials[handle].types.type[i]);
                credentials[handle].types.type[i] = NULL;
            }
        }

        credentials[handle].types.num = 0;
    }

    if (credentials[handle].credential_subjects.num) {
        for (int i = 0; i < DID_VC_CREDENTIALSUBJECT_NUM_MAX; i++) {
            if (credentials[handle].credential_subjects.vc[i].id) {
                free(credentials[handle].credential_subjects.vc[i].id);
                credentials[handle].credential_subjects.vc[i].id = NULL;
            }
        }

        credentials[handle].credential_subjects.num = 0;
    }

    if (credentials[handle].issuer.id) {
        free(credentials[handle].issuer.id);
        credentials[handle].issuer.id = NULL;
    }

    if (credentials[handle].issuance_date) {
        free(credentials[handle].issuance_date);
        credentials[handle].issuance_date = NULL;
    }

    if (credentials[handle].proofs.num) {
        for (int i = 0; i < DID_VC_PROOFS_NUM_MAX; i++) {
            did_vc_proof_destroy(&credentials[handle].proofs.proof[i]);            
        }

        credentials[handle].proofs.num = 0;
    }

    if (credentials[handle].expiration_date) {
        free(credentials[handle].expiration_date);
        credentials[handle].expiration_date = NULL;
    }

    did_vc_status_destroy(&credentials[handle].credential_status);

    if (credentials[handle].terms_of_use.num) {
        for (int i = 0; i < DID_VC_TERMOFUES_NUM_MAX; i++) {
            did_vc_termofuse_destroy(&credentials[handle].terms_of_use.TermOfUse[i]);
        }

        credentials[handle].terms_of_use.num = 0;
    }

    if (credentials[handle].evidences.num) {
        for (int i = 0; i < DID_VC_EVIDENCE_NUM_MAX; i++) {
            did_vc_evidence_destroy(&credentials[handle].evidences.Evidence[i]);
        }

        credentials[handle].evidences.num = 0;
    }

    if (credentials[handle].credential_schema.num) {
        for (int i = 0; i < DID_VC_SCHEMA_NUM_MAX; i++) {
            did_vc_schema_destroy(&credentials[handle].credential_schema.Schema[i]);
        }

        credentials[handle].credential_schema.num = 0;
    }

    if (credentials[handle].refresh_service.num) {
        for (int i = 0; i < DID_VC_REFRESHSERVIDE_NUM_MAX; i++) {
            if (credentials[handle].refresh_service.refreshservice[i].id) {
                free(credentials[handle].refresh_service.refreshservice[i].id);
                credentials[handle].refresh_service.refreshservice[i].id = NULL;
            }

            if (credentials[handle].refresh_service.refreshservice[i].type) {
                free(credentials[handle].refresh_service.refreshservice[i].type);
                credentials[handle].refresh_service.refreshservice[i].type = NULL;
            }
        }

        credentials[handle].refresh_service.num = 0;
    }

}

char* iotex_vc_serialize(VCHandle handle)
{
    cJSON *vc_root;
    char *vc_out = NULL;

    if (handle >= DID_VC_NUM_MAX)
        return NULL;

    vc_root = cJSON_CreateObject();

    if (1 == credentials[handle].Contexts.num) {
        cJSON_AddStringToObject(vc_root, "@context", credentials[handle].Contexts.context[0]);
    } else {
        cJSON *contexts = cJSON_CreateArray();

        for (int i = 0; i < credentials[handle].Contexts.num; i++) {
            if (credentials[handle].Contexts.context[i])
                cJSON_AddItemToArray(contexts, cJSON_CreateString(credentials[handle].Contexts.context[i]));
        }

        cJSON_AddItemToObject(vc_root, "@context", contexts);
    }

    if (credentials[handle].id)
        cJSON_AddStringToObject(vc_root, "id", credentials[handle].id);

    if (credentials[handle].types.num) {

        cJSON *types = cJSON_CreateArray();

        for (int i = 0; i < credentials[handle].types.num; i++) {
            if (credentials[handle].types.type[i])
                cJSON_AddItemToArray(types, cJSON_CreateString(credentials[handle].types.type[i]));
        }

        cJSON_AddItemToObject(vc_root, "type", types);        
    }

    if (credentials[handle].issuer.id)
            cJSON_AddStringToObject(vc_root, "issuer", credentials[handle].issuer.id);

    if (credentials[handle].issuance_date)
            cJSON_AddStringToObject(vc_root, "issuanceDate", credentials[handle].issuance_date);

    if (credentials[handle].credential_subjects.num) {

        cJSON *credentialSubject = cJSON_CreateObject();
        if (1 == credentials[handle].credential_subjects.num) {
            cJSON_AddStringToObject(credentialSubject, "id", credentials[handle].credential_subjects.vc[0].id);            
        }

        cJSON_AddItemToObject(vc_root, "credentialSubject", credentialSubject);
    }

    vc_out = cJSON_Print(vc_root);

    cJSON_Delete(vc_root);

    return vc_out;
}

void *iotex_vc_json(VCHandle handle)
{
    cJSON *vc_root;
    // char *vc_out = NULL;

    if (handle >= DID_VC_NUM_MAX)
        return NULL;

    vc_root = cJSON_CreateObject();

    if (1 == credentials[handle].Contexts.num) {
        cJSON_AddStringToObject(vc_root, "@context", credentials[handle].Contexts.context[0]);
    } else {
        cJSON *contexts = cJSON_CreateArray();

        for (int i = 0; i < credentials[handle].Contexts.num; i++) {
            if (credentials[handle].Contexts.context[i])
                cJSON_AddItemToArray(contexts, cJSON_CreateString(credentials[handle].Contexts.context[i]));
        }

        cJSON_AddItemToObject(vc_root, "@context", contexts);
    }

    if (credentials[handle].id)
        cJSON_AddStringToObject(vc_root, "id", credentials[handle].id);

    if (credentials[handle].types.num) {

        cJSON *types = cJSON_CreateArray();

        for (int i = 0; i < credentials[handle].types.num; i++) {
            if (credentials[handle].types.type[i])
                cJSON_AddItemToArray(types, cJSON_CreateString(credentials[handle].types.type[i]));
        }

        cJSON_AddItemToObject(vc_root, "type", types);        
    }

    if (credentials[handle].issuer.id)
            cJSON_AddStringToObject(vc_root, "issuer", credentials[handle].issuer.id);

    if (credentials[handle].issuance_date)
            cJSON_AddStringToObject(vc_root, "issuanceDate", credentials[handle].issuance_date);

    if (credentials[handle].credential_subjects.num) {

        cJSON *credentialSubject = cJSON_CreateObject();
        if (1 == credentials[handle].credential_subjects.num) {
            cJSON_AddStringToObject(credentialSubject, "id", credentials[handle].credential_subjects.vc[0].id);            
        }

        cJSON_AddItemToObject(vc_root, "credentialSubject", credentialSubject);
    }

    // vc_out = cJSON_Print(vc_root);

    // cJSON_Delete(vc_root); 

    return vc_root;
}

