#ifndef __IOTEX_DIDS_DID_H__
#define __IOTEX_DIDS_DID_H__

#include "include/jose/jwk.h"

#define DIDS_CONTEXT_NUM_MAX            4
#define DIDS_ALSO_KNOWN_AS_NUM_MAX      4
#define DIDS_CONTROLLERS_NUM_MAX        4
#define DIDS_VERIFICATION_METHOD_NUM_MAX        4

#define DEFAULT_CONTEXT "https://www.w3.org/ns/did/v1"

typedef char* DID;

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

typedef struct {
    unsigned int context_num;
    char *context[DIDS_CONTEXT_NUM_MAX];
} DIDContexts;

typedef struct {
    unsigned int known_as_num;
    char *known_as[DIDS_ALSO_KNOWN_AS_NUM_MAX];
} DIDKnown_As;

typedef struct {
    unsigned int controller_num;
    char *controllers[DIDS_CONTROLLERS_NUM_MAX];
} DIDControllers;

enum VerificationMethod_Type {
    VM_TYPE_DIDURL,
    VM_TYPE_RELATIVEDIDURL,
    VM_TYPE_MAP,
};

typedef struct {
    void *context;      // rename = "@context", property of a verification method map. Used if the verification method map uses some terms not defined in the containing DID document. skip if is none.
    char *id;           // id property ([DID URL][DIDURL]) of a verification method map.
    char *type;         // rename = "type", type of a verification method map Should be registered in [DID Specification registries - Verification method types]
    DID controller;
    JWK *public_key_jwk;    // rename = "publicKeyJwk", property of a verification method map, representing a [JSON Web Key][JWK]. Make sure this JWK does not have private key material
    char *public_key_pgp;   // skip if is none.
    char *public_key_base58;        // rename = "publicKeyBase58", deprecated. skip if is none.
    char *blockchain_account_id;    // rename = "blockchainAccountId", property encoding a [CAIP-10 Blockchain account id](crate::caip10::BlockchainAccountId). skip if is none.
    // TODO: map pub property_set: Option<Map<String, Value>>,   // Additional JSON properties.
} VerificationMethodMap;

typedef struct {
    enum VerificationMethod_Type type;
    union {
        DIDURL didurl;
        RelativeDIDURL rdidurl;
        VerificationMethodMap map;
    } Params;
} VerificationMethod;

enum ServiceEndpoint_type {
    SERVICE_ENDPOINT_TYPE_URI,
    SERVICE_ENDPOINT_TYPE_MAP,
};

typedef struct {
    enum ServiceEndpoint_type type;
    union {
        char *uri;
        char *map;
    } value;
} ServiceEndpoint;

typedef struct {
    char* id;
    char* type[4];                  // rename = "type"
    ServiceEndpoint endpoint[4];    // property of a service map, skip if is none
    // TODO: map property_set;
} DIDService;

typedef struct {
    char *type;     // rename = "type"
    // TODO: map property_set: Option<Map<String, Value>>,
} DIDProof;

typedef struct  {
    DIDContexts contexts;                   // "@context"      
    DID id;                                 // DID Subject id
    DIDKnown_As also_known_as;              // rename = "alsoKnownAs", expressing other URIs for the DID subject. skip_if_is_none
    DIDControllers controllers;             // rename = "controller", expressing [DID controllers(s). skip_if_is_none
    VerificationMethod verfication_method[DIDS_VERIFICATION_METHOD_NUM_MAX];  // rename = "verificationMethod", DID document, expressing [verification methods]. skip_if_is_none
    VerificationMethod authentication[DIDS_VERIFICATION_METHOD_NUM_MAX];      // rename = "authentication", property of a DID document, expressing [verification methods]. skip_if_is_none
    VerificationMethod assertion_method[DIDS_VERIFICATION_METHOD_NUM_MAX];    // rename = "assertionMethod", property of a DID document, expressing [verification methods]. skip_if_is_none
    VerificationMethod key_agreement[DIDS_VERIFICATION_METHOD_NUM_MAX];             // rename = "keyAgreement", property of a DID document, expressing [verification methods]. skip_if_is_none
    VerificationMethod capability_invocation[DIDS_VERIFICATION_METHOD_NUM_MAX];     // rename = "capabilityInvocation", property of a DID document, expressing [verification methods]. skip_if_is_none
    VerificationMethod capability_delegation[DIDS_VERIFICATION_METHOD_NUM_MAX];     // rename = "capabilityDelegation", property of a DID document, expressing [verification methods]. skip_if_is_none
//    VerificationMethod public_key[DIDS_VERIFICATION_METHOD_NUM_MAX];              // rename = "publicKey", property of a DID document, expressing [verification methods]. skip_if_is_none
    DIDService service[4]; // rename = "service",  generally as endpoints. skip_if_is_none
    DIDProof proof[4];     // rename = "proof",  over a DID document. skip_if_is_none 
    // TODO: map property_set: Option<Map<String, Value>>,          
} DIDDocument;

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
char *iotex_dids_get_default(char *did, JWK *jwk);

#endif