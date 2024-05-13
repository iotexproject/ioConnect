#ifndef __IOTEX_DIDS_DID_H__
#define __IOTEX_DIDS_DID_H__

#include "include/dids/common.h"
#include "include/jose/jwk.h"
#include "include/utils/cJSON/cJSON.h"

typedef char* DID;

typedef unsigned int    diddoc_handle_t;
typedef cJSON*          diddoc_property_handle_t;
typedef cJSON*          VerificationMethod_Map;

#define DIDS_CONTEXT_NUM_MAX                    4
#define DIDS_ALSO_KNOWN_AS_NUM_MAX              4
#define DIDS_CONTROLLERS_NUM_MAX                4
#define DIDS_VERIFICATION_METHOD_NUM_MAX        4

#define IOTEX_DIDDOC_DEFAULT_CONTEXT                       "https://www.w3.org/ns/did/v1"

#define IOTEX_DIDDOC_PARSE_TO_OBJECT(x)     cJSON_Parse(x)
#define IOTEX_DIDDOC_PROPERTY_DUPLICATE(x)  cJSON_Duplicate(x, true)  

#define IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT            0x00010000
#define IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID                 0x00020000
#define IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ALSO_KNOWN_AS      0x00030000
#define IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTROLLER         0x00040000
#define IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_SERVICE            0x00050000
#define IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_PROPERTY           0x00060000

// #define IOTEX_VC_BUILD_PROPERTY_TYPE_PROOF              0x07000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_STATUS             0x08000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_TERMOFUSE          0x09000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_EVIDENCE           0x0a000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_SCHEMA             0x0b000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_RS                 0x0c000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_EXP                0x0d000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_PROPERTY           0x0e000000
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_MIN                (IOTEX_VC_BUILD_PROPERTY_TYPE_CONTEXT)
// #define IOTEX_VC_BUILD_PROPERTY_TYPE_MAX                (IOTEX_VC_BUILD_PROPERTY_TYPE_PROPERTY)

#define IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_STRING         0x000001
#define IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_NUM            0x000002
#define IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_BOOL           0x000004
#define IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_JSON           0x000008

#define IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK           0x00000F
#define IOTEX_DIDDOC_BUILD_PROPERTY_MAIN_TYPE_MASK                  0xFFFF0000
#define IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_MASK                   0x0000FFFF

#define IOTEX_DIDDOC_GET_BUILD_PROPERTY_MAIN_TYPE(x)                (x & IOTEX_DIDDOC_BUILD_PROPERTY_MAIN_TYPE_MASK)
#define IOTEX_DIDDOC_GET_BUILD_PROPERTY_SUB_TYPE(x)                  (x & IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_MASK)

#define IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_VALID(x)               (IOTEX_DIDDOC_GET_BUILD_PROPERTY_SUB_TYPE(x) & IOTEX_DIDDOC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)

// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PROOF_VALID_MASK       (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_CS_VALID_MASK          (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ISSUER_VALID_MASK      (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_EVIDENCE_VALID_MASK    (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_STATUS_VALID_MASK      (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TERMOFUSE_VALID_MASK   (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_SCHEMA_VALID_MASK      (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_RS_VALID_MASK          (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_ID | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_TYPE | IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)
// #define IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PROPERTY_VALID_MASK    (IOTEX_VC_BUILD_PROPERTY_SUB_TYPE_PRIVATE_MASK)

#define IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID                   0x000001
#define IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE                 0x000002
#define IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON                  0x000003
#define IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK                  0x000004
#define IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_MULTIBASE            0x000005
#define IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_BASE58               0x000006

#define IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_MASK                 0x0000FFFF

#define IOTEX_DIDDOC_GET_BUILD_VM_MAP_TYPE(x)                  (x & IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_MASK)

#define IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ID                  0x000001
#define IOTEX_DIDDOC_BUILD_SERVICE_TYPE_TYPE                0x000002
#define IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ENDPOINT            0x000003

#define IOTEX_DIDDOC_BUILD_SERVICE_TYPE_MASK                0x0000FFFF

#define IOTEX_DIDDOC_GET_BUILD_SERVICE_TYPE(x)                  (x & IOTEX_DIDDOC_BUILD_SERVICE_TYPE_MASK)


#define IOTEX_DIDDOC_VM_PURPOSE_NAME_VERIFICATION_METHOD               "verificationMethod"
#define IOTEX_DIDDOC_VM_PURPOSE_NAME_AUTHENTICATION                    "authentication"
#define IOTEX_DIDDOC_VM_PURPOSE_NAME_ASSERTION_METHOD                  "assertionMethod"
#define IOTEX_DIDDOC_VM_PURPOSE_NAME_KEY_AGREEMENT                     "keyAgreement"
#define IOTEX_DIDDOC_VM_PURPOSE_NAME_CAPABILITY_INVOCATION             "capabilityInvocation"
#define IOTEX_DIDDOC_VM_PURPOSE_NAME_CAPABILITY_DELEGATION             "capabilityDelegation"
#define IOTEX_DIDDOC_VM_PURPOSE_NAME_PUBLIC_KEY                        "publicKey"

#define IOTEX_DIDDOC_PROPERTY_ID_BUFFER_SIZE               64
#define IOTEX_DIDDOC_PROPERTY_SERVICE_ID_BUFFER_SIZE       64

#define IOTEX_VERIFICATION_METHOD_PROPERTY_CON_BUFFER_SIZE       64

#define IOTEX_VERIFICATION_METHOD_TYPE_VALUE_JSONWEBKEY2020                                 "JsonWebKey2020"  
#define IOTEX_VERIFICATION_METHOD_TYPE_VALUE_ECDSASECP256K1VERIFICATIONKEY2019              "EcdsaSecp256k1VerificationKey2019"
#define IOTEX_VERIFICATION_METHOD_TYPE_VALUE_ED25519VEIFICATIONKEY2018                      "Ed25519VerificationKey2018"
#define IOTEX_VERIFICATION_METHOD_TYPE_VALUE_BLS12381G1KEY2020                              "Bls12381G1Key2020"
#define IOTEX_VERIFICATION_METHOD_TYPE_VALUE_BLS12381G2KEY2020                              "Bls12381G2Key2020"
#define IOTEX_VERIFICATION_METHOD_TYPE_VALUE_PGPVERIFICATIONKEY2021                         "PgpVerificationKey2021"
#define IOTEX_VERIFICATION_METHOD_TYPE_VALUE_RSAVERIFICATIONKEY2018                         "RsaVerificationKey2018"

enum VerificationMethod_Purpose {
    VM_PURPOSE_VERIFICATION_METHOD,
    VM_PURPOSE_AUTHENTICATION,
    VM_PURPOSE_ASSERTION_METHOD,
    VM_PURPOSE_KEY_AGREEMENT,
    VM_PURPOSE_CAPABILITY_INVOCATION,
    VM_PURPOSE_CAPABILITY_DELEGATION,
    VM_PURPOSE_PUBLIC_KEY,
    VM_PURPOSE_MAX,
};

enum VerificationMethod_Type {
    VM_TYPE_DIDURL,
    VM_TYPE_RELATIVEDIDURL,
    VM_TYPE_MAP,
};

enum ServiceEndpoint_type {
    SERVICE_ENDPOINT_TYPE_URI,
    SERVICE_ENDPOINT_TYPE_MAP,
};

enum VerificationMethod_TypeValue {
    VMTypeNone,
    JsonWebKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Ed25519VerificationKey2018,
    Bls12381G1Key2020,
    Bls12381G2Key2020,
    PgpVerificationKey2021,
    RsaVerificationKey2018,
};

enum VerificationMethod_PublicKeyType {
    VERIFICATION_METHOD_PUBLIC_KEY_TYPE_JWK,
    VERIFICATION_METHOD_PUBLIC_KEY_TYPE_MULTIBASE,
    VERIFICATION_METHOD_PUBLIC_KEY_TYPE_BASE58,
};

typedef struct _DID_Contexts {
    cJSON *contexts;                // JSON_Arrary
} DIDDoc_Contexts;

typedef struct _DID_AlsoKnownAs {
    cJSON *alsoKnownAs;             // JSON_Arrary
} DIDDoc_AlsoKnownAs;

typedef struct _DID_Controller {
    cJSON *controllers;             // JSON_Arrary
} DIDDoc_Controllers;

typedef struct _DIDDoc_VerificationMethod {
    enum VerificationMethod_Purpose purpose;
    enum VerificationMethod_Type    type;
    cJSON *vm;                                  // JSON_Arrary [VM_TYPE_DIDURL] or JSON_Arrary [VM_TYPE_MAP]
} DIDDoc_VerificationMethod;

typedef struct _DIDDoc_ServicEndpoint {
    enum ServiceEndpoint_type type;
    cJSON *endpoint;                // JSON_Arrary [SERVICE_ENDPOINT_TYPE_URI] or JSON_Object [SERVICE_ENDPOINT_TYPE_MAP]
} DIDDoc_ServiceEndpoint;

typedef struct _DIDDoc_Service {
    char id[IOTEX_DIDDOC_PROPERTY_SERVICE_ID_BUFFER_SIZE];
    cJSON *type;            // JSON_Arrary
    cJSON *endpoints;       // JSON_Arrary, property of a service map, skip if is none
} DIDDoc_Service;

typedef struct _DIDDoc_Services {
    cJSON *Services;                // JSON_Arrary
} DIDDoc_Services;

typedef struct _DIDDoc {
    DIDDoc_Contexts contexts;
    char id[IOTEX_DIDDOC_PROPERTY_ID_BUFFER_SIZE];
    DIDDoc_AlsoKnownAs aka;
    DIDDoc_Controllers cons;
    DIDDoc_VerificationMethod vm;
    DIDDoc_VerificationMethod auth;
    DIDDoc_VerificationMethod assertion;
    DIDDoc_VerificationMethod keyagreement;
    DIDDoc_VerificationMethod ci;
    DIDDoc_VerificationMethod cd;
    DIDDoc_VerificationMethod publickey;
    DIDDoc_Services services;
    void *property_set;                      // Property Set : JSON_Object
} DIDDoc;

typedef struct _VerificationMethod_Info {
    char *id;
    enum VerificationMethod_Purpose         purpose;
    enum VerificationMethod_TypeValue       type;
    enum VerificationMethod_PublicKeyType   pubkey_type;
    union {
        char *multibase;
        char *base58;
        JWK *jwk;
    } pk_u;
} VerificationMethod_Info;

///////////////////////////////////////////////////////////////////////////////////////////
enum RelativeDIDURLPath {
    Absolute,
    NoScheme,
    Empty,
};

enum VerificationRelationship {
    VR_None,
    AssertionMethod,
    Authentication,
    KeyAgreement,
    ContractAgreement,
    CapabilityInvocation,
    CapabilityDelegation, 
};

enum DIDsError {

    DIDERR_KeyMismatch,                // "Key mismatch"
    DIDERR_MissingKey,                 // "JWT key not found"
    DIDERR_MultipleKeyMaterial,        // "A verification method MUST NOT contain multiple verification material properties for the same material. (DID Core)"
    DIDERR_DIDURL,                     // "Invalid DID URL"
    DIDERR_DIDURLDereference,          // "Unable to dereference DID URL : %s"
    DIDERR_UnexpectedDIDFragment,      // "Unexpected DID fragment"
    DIDERR_InvalidContext,             // "Invalid context"
    DIDERR_ControllerLimit,            // "DID controller limit exceeded"
    DIDERR_MissingContext,             // "Missing context"
    DIDERR_MissingDocumentId,          // "Missing document ID"
    DIDERR_ExpectedObject,             // "Expected object"
    DIDERR_UnsupportedVerificationRelationship,    // "Unsupported verification relationship"
    DIDERR_ResourceNotFound,                       // "Resource not found %"
    DIDERR_ExpectedStringPublicKeyMultibase,       // "Expected string for publicKeyMultibase"
    DIDERR_RepresentationNotSupported,             // "RepresentationNotSupported"
    DIDERR_Multibase,                              // "Error parsing or producing multibase"
    DIDERR_SerdeJSON,
    DIDERR_SerdeUrlEncoded,
    DIDERR_BlockchainAccountIdParse,
    DIDERR_BlockchainAccountIdVerify,
    DIDERR_FromHex,
    DIDERR_Base58,
    DIDERR_HexString,                              // Expected string beginning with '0x'    
    DIDERR_UnableToResolve,                        // "Unable to resolve: %s"
    DIDERR_JWK,
};

typedef struct {
    char* did;
    char* path_abempty;
    char* query;
    char* fragment;
} DIDURL;

typedef struct {
    enum RelativeDIDURLPath type;
    char *relative_didurl;
    char *query;
    char *fragment;
} RelativeDIDURL;

typedef struct {
    char* did;
    char* path;
    char* query;
} PrimaryDIDURL;

typedef char* (*did_method_name)(void); 
typedef char* (*did_method_generate)(JWK *jwk);
typedef char* (*did_method_from_transaction)(char *);
typedef char* (*did_method_submit_transaction)(char *);
typedef char* (*did_method_create)(char *);
typedef char* (*did_method_update)(char *);
typedef char* (*did_method_recover)(char *);
typedef char* (*did_method_deactivate)(char *);
typedef char* (*did_method_to_resolver)(void);

typedef struct {
    did_method_name name;
    did_method_generate generate;
    did_method_from_transaction from_transaction;
    did_method_submit_transaction submit_transaction;
    did_method_create create;
    did_method_update update;
    did_method_recover recover;
    did_method_deactivate deactivate;
    did_method_to_resolver resolver;
} DID_Method;

enum VerificationRelationship get_verification_relationship_default(void);
enum VerificationRelationship get_verification_relationship_from_str(char *str);
char* verification_relationship_to_str(enum VerificationRelationship ship);
char* verification_relationship_to_iri(enum VerificationRelationship ship);

char* iotex_did_generate(char *name, JWK *jwk);

DIDDoc* iotex_diddoc_new(void);
void iotex_diddoc_destroy(DIDDoc *doc);

DIDDoc_VerificationMethod* iotex_diddoc_verification_method_new(DIDDoc* diddoc, enum VerificationMethod_Purpose purpose, enum VerificationMethod_Type type);
VerificationMethod_Map iotex_diddoc_verification_method_map_new(void);
did_status_t iotex_diddoc_verification_method_map_set(VerificationMethod_Map map, unsigned int build_type, void *value);
did_status_t iotex_diddoc_verification_method_set(DIDDoc_VerificationMethod *vm, enum VerificationMethod_Type type, void *value);
did_status_t iotex_diddoc_property_set(DIDDoc *diddoc, unsigned int build_type, char *name, void *value);

DIDDoc_ServiceEndpoint* iotex_diddoc_service_endpoint_new(enum ServiceEndpoint_type type);
DIDDoc_Service* iotex_diddoc_service_new(void);
did_status_t iotex_diddoc_service_endpoint_set(DIDDoc_ServiceEndpoint* ServiceEndpoint, enum ServiceEndpoint_type type, void *value);
did_status_t iotex_diddoc_service_set(DIDDoc_Service* Service, unsigned int build_type, void *value);

char *iotex_diddoc_serialize(DIDDoc *diddoc, bool format);

DIDDoc *iotex_diddoc_parse(char *diddoc_serialize);
unsigned int iotex_diddoc_verification_method_get_num(DIDDoc *diddoc, enum VerificationMethod_Purpose purpose);
void iotex_verification_method_info_destroy(VerificationMethod_Info *info);
VerificationMethod_Info *iotex_diddoc_verification_method_get(DIDDoc *diddoc, enum VerificationMethod_Purpose purpose, unsigned int idx);         


#endif