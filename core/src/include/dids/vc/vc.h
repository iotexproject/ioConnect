#ifndef __IOTEX_DID_VC__
#define __IOTEX_DID_VC__

#include "include/dids/did/did.h"

#ifndef DID_VC_CONTEXT_NUM_MAX
#define DID_VC_CONTEXT_NUM_MAX      4
#endif

#ifndef DID_VC_TYPE_NUM_MAX
#define DID_VC_TYPE_NUM_MAX         4
#endif

#ifndef DID_VC_CREDENTIALSUBJECT_NUM_MAX
#define DID_VC_CREDENTIALSUBJECT_NUM_MAX         4
#endif

#ifndef DID_VC_PROOFS_NUM_MAX
#define DID_VC_PROOFS_NUM_MAX       4
#endif

#ifndef DID_VC_TERMOFUES_NUM_MAX
#define DID_VC_TERMOFUES_NUM_MAX    4
#endif

#ifndef DID_VC_EVIDENCE_NUM_MAX
#define DID_VC_EVIDENCE_NUM_MAX     4
#endif

#ifndef DID_VC_SCHEMA_NUM_MAX
#define DID_VC_SCHEMA_NUM_MAX       4
#endif

#ifndef DID_VC_REFRESHSERVIDE_NUM_MAX
#define DID_VC_REFRESHSERVIDE_NUM_MAX       4
#endif

#ifndef DID_VC_NUM_MAX
#define DID_VC_NUM_MAX              4
#endif

typedef enum VerificationRelationship ProofPurpose;
typedef unsigned int VCHandle;

#define IOTEX_CREDENTIALS_V1_CONTEXT "https://www.w3.org/2018/credentials/v1"

enum ProofSuiteType {
    RsaSignature2018,                       // rename = "rsa"
    Ed25519Signature2018,                   // rename = "ed25519"
    Ed25519Signature2020,                   // rename = "ed25519"
    DataIntegrityProof,
    Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,      // rename = "tezos"
    P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,         // rename = "tezos"
    EcdsaSecp256k1Signature2019,            // rename = "secp256k1"
    EcdsaSecp256k1RecoverySignature2020,    // rename = "secp256k1"
    Eip712Signature2021,                    // rename = "eip"
    EthereumPersonalSignature2021,          // rename = "eip"
    EthereumEip712Signature2021,            // rename = "eip"
    TezosSignature2021,                     // rename = "tezos"
    TezosJcsSignature2021,                  // rename = "tezos"
    SolanaSignature2021,                    // rename = "solana"
    AleoSignature2021,                      // rename = "aleo"
    JsonWebSignature2020,                   // rename = "w3c"
    EcdsaSecp256r1Signature2019,            // rename = "secp256r1"
    CLSignature2019,
    NonJwsProof,                         
    AnonCredPresentationProofv1,            // rename = "ex:AnonCredPresentationProofv1"
    AnonCredDerivedCredentialv1,            // rename = "ex:AnonCredPresentationProofv1"
};

enum DataIntegrityCryptoSuite {
    Eddsa2022,          // rename = "eddsa-2022"
    JcsEddsa2022,       // rename = "json-eddsa-2022"
    Ecdsa2019,          // rename = "ecdsa-2019"
    JcsEcdsa2019,       // rename = "jcs-ecdsa-2019"
};

typedef struct {
    unsigned int num;
    char *context[DID_VC_CONTEXT_NUM_MAX];
} VC_Contexts;

typedef struct {
    unsigned int num;
    char *type[DID_VC_TYPE_NUM_MAX];
} VC_Types;

typedef struct {
    char * id;              // skip if it is none
    // TODO：MAP property_set <string, value>, skip if it is none
} VC_CredentialSubject;

typedef struct {
    unsigned int num;
    VC_CredentialSubject vc[DID_VC_CREDENTIALSUBJECT_NUM_MAX];
} VC_CredentialSubjects;

typedef struct {
    char * id;
    // TODO：MAP property_set <string, value>, skip if it is none
} VC_Issuer;

typedef struct {
    void *context;              // rename = "@context", skip if it's value is null;
    enum ProofSuiteType type;   // rename = "type"
    ProofPurpose proof_purpose; // skip if it is none
    char *proof_value;          // skip if it is none
    char *challenge;            // skip if it is none
    char *creator;              // skip if it is none
    char *verification_method;  // skip if it is none. Note: ld-proofs specifies verificationMethod as a "set of parameters", but all examples use a single string.
    char *created;              // skip if it is none
    char *domain;               // skip if it is none
    char *nonce;                // skip if it is none
    char *jws;                  // skip if it is none
    enum DataIntegrityCryptoSuite cryptosuite;      // skip if it is none

    // TODO：MAP property_set <string, value>, skip if it is none

} VC_Proof;

typedef struct {
    unsigned int num;
    VC_Proof proof[DID_VC_PROOFS_NUM_MAX];    
} VC_Proofs;

typedef struct  {
    char *id;
    char *type;  // rename = "type"

    // TODO：MAP property_set <string, value>, skip if it is none

} VC_Status;

typedef struct  {
    char *id;           // skip if it is none
    char *type;         // rename = "type"

    // TODO：MAP property_set <string, value>, skip if it is none

} VC_TermOfUse;

typedef struct {
    unsigned int num;
    VC_TermOfUse TermOfUse[DID_VC_TERMOFUES_NUM_MAX];    
} VC_TermsOfUse;

typedef struct  {
    char *id;           // skip if it is none
    VC_Types types;     // rename = "type"

    // TODO：MAP property_set <string, value>, skip if it is none

} VC_Evidence;

typedef struct {
    unsigned int num;
    VC_Evidence Evidence[DID_VC_EVIDENCE_NUM_MAX];    
} VC_Evidences;

typedef struct  {
    char *id;
    char *type;  // rename = "type"

    // TODO：MAP property_set <string, value>

} VC_Schema;

typedef struct {
    unsigned int num;
    VC_Schema Schema[DID_VC_SCHEMA_NUM_MAX];    
} VC_Schemas;

typedef struct  {
    char *id;
    char *type;  // rename = "type"

    // TODO：MAP property_set <string, value>

} VC_RefreshService;

typedef struct {
    unsigned int num;
    VC_RefreshService refreshservice[DID_VC_REFRESHSERVIDE_NUM_MAX];    
} VC_RefreshServices;

typedef struct {
    VC_Contexts Contexts;                           // rename = "@context"
    char* id;                                       // skip if it is none
    VC_Types types;                                 // rename = "type"
    VC_CredentialSubjects credential_subjects;
    VC_Issuer issuer;                               // skip if it is none
    char* issuance_date;                            // rename = "issuanceDate", skip if it is none
    VC_Proofs proofs;                               // skip if it is none
    char* expiration_date;                          // skip if it is none
    VC_Status credential_status;                    // skip if it is none
    VC_TermsOfUse terms_of_use;                     // skip if it is none
    VC_Evidences evidences;                         // skip if it is none
    VC_Schemas credential_schema;                   // skip if it is none
    VC_RefreshServices refresh_service;             // skip if it is none

    // TODO：MAP property_set <string, value>, skip if it is none

} Credential;

VCHandle iotex_vc_new(void);
int iotex_vc_add_context(VCHandle handle, char *context);
int iotex_vc_add_id(VCHandle handle, char *id);
int iotex_vc_update_id(VCHandle handle, char *id, int isfree);
int iotex_vc_add_type(VCHandle handle, char *type);
int iotex_vc_add_issuer(VCHandle handle, char *issuer);
int iotex_vc_update_issuer(VCHandle handle, char *issuer, int isfree);
int iotex_vc_add_issuance_date(VCHandle handle, char *issuance_date);
int iotex_vc_update_issuance_date(VCHandle handle, char *issuance_date, int isfree);
int iotex_vc_add_credential_subjects(VCHandle handle, char *id);

char* iotex_vc_serialize(VCHandle handle);
void *iotex_vc_json(VCHandle handle);


#endif
