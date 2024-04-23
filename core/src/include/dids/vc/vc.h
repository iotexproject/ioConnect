#ifndef __IOTEX_VERIFIABLE_CREDENTIAL_H__
#define __IOTEX_VERIFIABLE_CREDENTIAL_H__

#include "include/dids/did/did.h"
#include "include/utils/cJSON/cJSON.h"

#define IOTEX_CREDENTIALS_V1_CONTEXT "https://www.w3.org/2018/credentials/v1"

typedef unsigned int vc_handle_t;
typedef cJSON* property_handle_t;

#define IOTEX_VC_PARSE_TO_OBJECT(x)     cJSON_Parse(x)  

#define IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT            0x01000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_ID                 0x02000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_TYPE               0x03000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_CS                 0x04000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER             0x05000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_ISSUER_DATE        0x06000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_PROOF              0x07000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_STATUS             0x08000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_TERMOFUSE          0x09000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_EVIDENCE           0x0a000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_SCHEMA             0x0b000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_RS                 0x0c000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_EXP                0x0d000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_PROPERTY           0x0e000000
#define IOTEX_VC_BUILD_PROPERTY_TYPE_MIN                (IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT)
#define IOTEX_VC_BUILD_PROPERTY_TYPE_MAX                (IOTEX_VC_BUILD_PROPERTY_TYPE_PROPERTY)

#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_STRING         0x000001
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_NUM            0x000002
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_BOOL           0x000004
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_JSON           0x000008
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID                     0x000010
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE                   0x000020

#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK   0x000F
#define IOTEX_VC_BUILD_PROPERTY_MAIN_TYPE_MASK          0xFF000000
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_MASK           0x00FFFFFF

#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PROOF_VALID_MASK       (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_CS_VALID_MASK          (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ISSUER_VALID_MASK      (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_EVIDENCE_VALID_MASK    (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_STATUS_VALID_MASK      (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TERMOFUSE_VALID_MASK   (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_SCHEMA_VALID_MASK      (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_RS_VALID_MASK          (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
#define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PROPERTY_VALID_MASK    (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)

#define IOTEX_VC_PROOF_PROPERTY_CONTEXT_NAME                "@context"
#define IOTEX_VC_PROOF_PROPERTY_PURPOSE_NAME                "proofPurpose"
#define IOTEX_VC_PROOF_PROPERTY_VALUE_NAME                  "proofValue"
#define IOTEX_VC_PROOF_PROPERTY_CHALLENGE_NAME              "challenge"
#define IOTEX_VC_PROOF_PROPERTY_VERIFICATION_METHOD_NAME    "verificationMethod"
#define IOTEX_VC_PROOF_PROPERTY_CREATED_NAME                "created"
#define IOTEX_VC_PROOF_PROPERTY_EXPIRES_NAME                "expires"
#define IOTEX_VC_PROOF_PROPERTY_DOMAIN_NAME                 "domain"
#define IOTEX_VC_PROOF_PROPERTY_NONCE_NAME                  "nonce"
#define IOTEX_VC_PROOF_PROPERTY_CRYPTOSUITE_NAME            "cryptosuite"

#define IOTEX_VC_PROPERTY_ID_BUFFER_SIZE                64
#define IOTEX_VC_PROPERTY_EXP_DATE_BUFFER_SIZE          64
#define IOTEX_VC_PROPERTY_ISSUANCE_DATE_BUFFER_SIZE     32

enum ProofSuiteType {
    DataIntegrityProof = 0,
    Ed25519Signature2020,
    Ed25519Signature2018,
    EcdsaSecp256k1Signature2019,
    EcdsaSecp256r1Signature2019,
    RsaSignature2018,
    JsonWebSignature2020,
    ProofSuiteTypeMax,
};

enum DataIntegrityCryptoSuite {
    Eddsa2022 = 0,                          // rename = "eddsa-2022"
    JcsEddsa2022,                           // rename = "json-eddsa-2022"
    Ecdsa2019,                              // rename = "ecdsa-2019"
    JcsEcdsa2019,                           // rename = "jcs-ecdsa-2019"
    DataIntegrityCryptoSuiteMax,
};

typedef struct _VC_Contexts {
    cJSON *contexts;                // JSON_Arrary
} VC_Contexts;

typedef struct _VC_Types {
    cJSON *typs;                    // JSON_Arrary
} VC_Types;

typedef struct _VC_CredentialSubject {
    cJSON *cs;                      // CredentialSubject : JSON_Object. SubType [vc_cs_id]
} VC_CredentialSubject;

typedef struct _VC_CredentialSubjects {
    cJSON *css;                     // CredentialSubjects : JSON_Array.
} VC_CredentialSubjects;

typedef struct _VC_Issuer {
    cJSON *issuer;                  // JSON_Object. SubType [vc_issuer_id, vc_issuer_private]
} VC_Issuer;

typedef struct _VC_Proof {
    cJSON *proof;                   // JSON_Object. SubType [p_context, p_type, p_purpose, p_value, p_challenge, p_creator, p_verification_method
                                    //                       p_created, p_domain, p_nonce, p_jws, p_cryptosuit, p_private ]
} VC_Proof;

typedef struct _VC_Proofs {
    cJSON *proofs;                  // JSON_Array.
} VC_Proofs;

typedef struct _VC_Status {
    cJSON *status;                  // JSON_Object. SubType [vc_status_id, vc_status_type, vc_status_private]
} VC_Status;

typedef struct _VC_TermOfUse {
    cJSON *termofuse;               // JSON_Object. SubType [vc_termofuse_id, vc_termofuse_type, vc_termofuse_private]
} VC_TermOfUse;

typedef struct _VC_TermsOfUse {
    cJSON *termsofuse;              // JSON_Array.
} VC_TermsOfUse;

typedef struct _VC_Evidence {
    cJSON *evidence;                // JSON_Object. SubType [vc_evidence_id, vc_evidence_type, vc_evidence_private]
} VC_Evidence;

typedef struct _VC_Evidences {
    cJSON *evidences;               // JSON_Array.
} VC_Evidences;

typedef struct _VC_Schema {
    cJSON *schema;                  // JSON_Object. SubType [vc_schema_id, vc_schema_type, vc_schema_private]
} VC_Schema;

typedef struct _VC_Schemas {
    cJSON *schemas;                 // JSON_Array.
} VC_Schemas;

typedef struct _VC_RefreshService {
    cJSON *rs;                      // RefreshService : JSON_Object. SubType [vc_schema_id, vc_schema_type, vc_schema_private]
} VC_RefreshService;

typedef struct _VC_RefreshServices {
    cJSON *rss;                     // RefreshServices : JSON_Array.
} VC_RefreshServices;

typedef struct _VerifiableCredential {
    VC_Contexts contests;
    char id[IOTEX_VC_PROPERTY_ID_BUFFER_SIZE];
    VC_Types types;
    VC_CredentialSubjects css;
    VC_Issuer issuer;
    char issuance_date[IOTEX_VC_PROPERTY_ISSUANCE_DATE_BUFFER_SIZE];
    VC_Proofs proofs;
    char exp_date[IOTEX_VC_PROPERTY_EXP_DATE_BUFFER_SIZE];
    VC_Status status;
    VC_TermsOfUse terms_of_use;
    VC_Evidences evidences;
    VC_Schemas schemas;
    VC_RefreshServices refresh_services;
    void *property_set;                      // Property Set : JSON_Object
} VerifiableCredential;

vc_handle_t iotex_vc_new(void);
did_status_t iotex_vc_destroy(vc_handle_t handle);
did_status_t iotex_vc_property_set(vc_handle_t handle, unsigned int build_type, char *name, void *value);
void * iotex_vc_property_get(char *vc_serialize, unsigned int build_type, char *name, int idx);

property_handle_t iotex_vc_sub_property_new(void);
did_status_t iotex_vc_sub_property_destroy(property_handle_t handle);
did_status_t iotex_vc_sub_property_set(property_handle_t handle, unsigned int build_type, char *name, void *value);

char *iotex_get_proof_suite_type_string(enum ProofSuiteType type);
char *iotex_get_data_intergrity_cryptosuite_string(enum DataIntegrityCryptoSuite type);

char *iotex_vc_serialize(vc_handle_t handle, bool format);

#endif
