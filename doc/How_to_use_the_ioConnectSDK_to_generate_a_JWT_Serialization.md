

# How to use the ioConnect SDK to generate a JWT Serialization 

JSON Web Token (JWT) is a compact claims representation format intended for space constrained environments such as HTTP Authorization headers and URI query parameters. JWTs encode claims to be transmitted as a JSON [RFC7159] object that is used as the payload of a JSON Web Signature (JWS) [JWS] structure or as the plaintext of a JSON Web Encryption (JWE) [JWE] structure, enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted. JWTs are always represented using the JWS Compact Serialization or the JWE Compact Serialization.



## JSON Web Token (JWT) Overview

JWTs represent a set of claims as a JSON object that is encoded in a JWS and/or JWE structure. This JSON object is the JWT Claims Set. As per Section 4 of RFC 7159 [RFC7159], the JSON object consists of zero or more name/value pairs (or members), where the names are strings and the values are arbitrary JSON values. These members are the claims represented by the JWT. This JSON object MAY contain whitespace and/or line breaks before or after any JSON values or structural characters, in accordance with Section 2 of RFC 7159 [RFC7159].

The member names within the JWT Claims Set are referred to as Claim Names. The corresponding values are referred to as Claim Values. The contents of the JOSE Header describe the cryptographic operations applied to the JWT Claims Set. If the JOSE Header is for a JWS, the JWT is represented as a JWS and the claims are digitally signed or MACed, with the JWT Claims Set being the JWS Payload. If the JOSE Header is for a JWE, the JWT is represented as a JWE and the claims are encrypted, with the JWT Claims Set being the plaintext encrypted by the JWE. A JWT may be enclosed in another JWE or JWS structure to create a Nested JWT, enabling nested signing and encryption to be performed. A JWT is represented as a sequence of URL-safe parts separated by period (’.’) characters. Each part contains a base64url-encoded value. The number of parts in the JWT is dependent upon the representation of the resulting JWS using the JWS Compact Serialization or JWE using the JWE Compact Serialization.



## JWT Claims

The JWT Claims Set represents a JSON object whose members are the claims conveyed by the JWT. The Claim Names within a JWT Claims Set MUST be unique; JWT parsers MUST either reject JWTs with duplicate Claim Names or use a JSON parser that returns only the lexically last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript]. The set of claims that a JWT must contain to be considered valid is context dependent and is outside the scope of this specification. Specific applications of JWTs will require implementations to understand and process some claims in particular ways. However, in the absence of such requirements, all claims that are not understood by implementations MUST be ignored.

There are three classes of JWT Claim Names: Registered Claim Names, Public Claim Names, and Private Claim Names.

### Registered Claim Names

The following Claim Names are registered in the IANA "JSON Web Token Claims" registry established by Section 10.1. None of the claims defined below are intended to be mandatory to use or implement in all cases, but rather they provide a starting point for a set of useful, interoperable claims. Applications using JWTs should define which specific claims they use and when they are required or optional. All the names are short because a core goal of JWTs is for the representation to be compact.

- "iss" (Issuer) Claim
- "sub" (Subject) Claim
- "aud" (Audience) Claim
- "exp" (Expiration Time) Claim
- "nbf" (Not Before) Claim
- "iat" (Issued At) Claim
- "jti" (JWT ID) Claim

### Public Claim Names

Claim Names can be defined at will by those using JWTs. However, in order to prevent collisions, any new Claim Name should either be registered in the IANA "JSON Web Token Claims" registry established by Section 10.1 or be a Public Name: a value that contains a Collision-Resistant Name. In each case, the definer of the name or value needs to take reasonable precautions to make sure they are in control of the part of the namespace they use to define the Claim Name.

### Private Claim Names

A producer and consumer of a JWT MAY agree to use Claim Names that are Private Names: names that are not Registered Claim Names (Section 4.1) or Public Claim Names (Section 4.2). Unlike Public Jones, et al. Standards Track [Page 10] RFC 7519 JSON Web Token (JWT) May 2015 Claim Names, Private Claim Names are subject to collision and should be used with caution.



## Standards and Protocols

- **Internet Engineering Task Force (IETF)**:
- [RFC 7519: JSON Web Token (JWT) (rfc-editor.org)](https://www.rfc-editor.org/rfc/rfc7519)



## API

### claim：

```c
// Generate a JWT claim handle.
// Params [void] : None
// Return [JWTClaim_handle] : a a JWT claim handle if successful, or NULL if failed.

JWTClaim_handle iotex_jwt_claim_new(void);
```



```c
// Destroy a JWT claim.
// Params [JWTClaim_handle] : a JWT claim handle from "iotex_jwt_claim_new()".
// Return [void] : None.

void iotex_jwt_claim_destroy(JWTClaim_handle handle);
```



```c
// To set a value to a Specified jwt claim.
// Params [JWTClaim_handle] : a JWT claim handle from "iotex_jwt_claim_new()".
// Params [enum JWTClaimType] : a type of JWT claim. See Definition.
// Params [name] : The name of the claim value needs to be set. Ignored if it is a Registered Claim.
// Params [value] : The value of claim needs to be set.
// Return [jose_status_t] : The return status of this function.

jose_status_t iotex_jwt_claim_set_value(JWTClaim_handle handle, enum JWTClaimType type, char *name, void *value);
```



```c
// To get a value from a jwt or a claim serialization.
// Params [JWTClaim_handle] : a JWT claim handle from "iotex_jwt_claim_new()".
// Params [enum JWTType] : a type of JWT. See Definition.
// Params [enum JWTClaimType] : a type of JWT claim. See Definition.
// Params [name] : The name of the claim value needs to be set. Ignored if it is a Registered Claim.
// Return [void *] : The return the value of PARAM 1 if successful, or NULL if failed.

void * iotex_jwt_claim_get_value(char *jwt_serialize, enum JWTType jwt_type, enum JWTClaimType type, char *name);
```



```c
// To generate a jwt claim serialization.
// Params [JWTClaim_handle] : a JWT claim handle from "iotex_jwt_claim_new()".
// Params [format] : Generate a formatted information if true, otherwise unformatted information is generated.
// Return [char *] : a JWT claim Serialization if successful, or NULL if failed.

char *iotex_jwt_claim_serialize(JWTClaim_handle handle, bool format);
```



### JWT:

```c
// Generate a JWT serialization.
//
// Params [JWTClaim_handle] : a JWT claim handle from "iotex_jwt_claim_new()".
// Params [enum JWTType] : a type of JWT. See Definition.
// Params [enum JWAlogrithm] : JWA supported algorithms. See Definition.
// Params [JWK *] : The JWK pointer to be used.
//
// Return [char *] : a JWT serialization if successful, or NULL if failed.

char *iotex_jwt_serialize(JWTClaim_handle handle, enum JWTType type, enum JWAlogrithm alg, JWK *jwk);
```



```c
// Verify a JWT serialization.
//
// Params [jwt_serialize] : a jwt serialization from "iotex_jwt_serialize()".
// Params [enum JWTType] : a type of JWT. See Definition.
// Params [enum JWAlogrithm] : JWA supported algorithms. See Definition.
// Params [JWK *] : The JWK pointer to be used.
//
// Return [bool] : true: verification passed, false: verification failed.

bool iotex_jwt_verify(char *jwt_serialize, enum JWTType type, enum JWAlogrithm alg, JWK *jwk);
```



## Definition

### enum JWTClaimType

```c
enum JWTClaimType {
    JWT_CLAIM_TYPE_ISS,
    JWT_CLAIM_TYPE_SUB,
    JWT_CLAIM_TYPE_AUD,
    JWT_CLAIM_TYPE_EXP,
    JWT_CLAIM_TYPE_NBF,
    JWT_CLAIM_TYPE_IAT,
    JWT_CLAIM_TYPE_JTI,
    JWT_CLAIM_TYPE_PRIVATE_STRING,
    JWT_CLAIM_TYPE_PRIVATE_NUM,
    JWT_CLAIM_TYPE_PRIVATE_BOOL,
    JWT_CLAIM_TYPE_PRIVATE_JSON,
};
```



### enum JWTType

```c
enum JWTType {
  JWT_TYPE_JWS,
  JWT_TYPE_JWE,
};
```



### enum JWAlogrithm

```c
enum JWAlogrithm {
    None,
    HS256,     
    HS384,
    HS512,
    RS256,     
    RS384,
    RS512,
    PS256,     
    PS384,
    PS512,
    EdDSA,
    ES256,     
    ES384,
    ES256K,
    ES256KR,
};
```



## Example

```c
JWTClaim_handle jwt_claim_handle = iotex_jwt_claim_new();
if (NULL == jwt_claim_handle) {
    printf("Fail to Generate a jwt claim\n");
    return;
}

did_status = iotex_jwt_claim_set_value(jwt_claim_handle, JWT_CLAIM_TYPE_ISS, NULL, (void *)did_key);
if (vc_serialize)
    did_status = iotex_jwt_claim_set_value(jwt_claim_handle, JWT_CLAIM_TYPE_PRIVATE_JSON, "vp", (void *)IOTEX_VC_PARSE_TO_OBJECT(vc_serialize));

char *jwt_serialize = iotex_jwt_serialize(jwt_claim_handle, JWT_TYPE_JWS, ES256, jwk);    
if (jwt_serialize)
    printf("JWT[JWS]:\n%s\n", jwt_serialize);

iotex_jwt_claim_destroy(jwt_claim_handle);

if (iotex_jwt_verify(jwt_serialize, JWT_TYPE_JWS, ES256, jwk))
    printf("Success to JWT [JWS] Verify\n");
else
    printf("Fail to JWT [JWS] Verify\n");

char *iss = iotex_jwt_claim_get_value(jwt_serialize, JWT_TYPE_JWS, JWT_CLAIM_TYPE_ISS, NULL);
if (iss) 
    printf("Get ISS : %s\n", iss);

cJSON *vp = iotex_jwt_claim_get_value(jwt_serialize, JWT_TYPE_JWS, JWT_CLAIM_TYPE_PRIVATE_JSON, "vp");
if (vp)
    printf("Get Private Json : %s\n", cJSON_Print(vp));
```



## output

```bash
JWT[JWS]:
eyJhbGciOiJFUzI1NiJ9.ewoJImlzcyI6CSJkaWQ6aW86MHhkYzYyNzI0MDliNDhlMmQ5NTNmNDY1MzVhZjNhYzcwY2ZjYTg2ZmFiIiwKCSJ2cCI6CXsKCQkiQGNvbnRleHQiOglbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sCgkJImlkIjoJImh0dHA6Ly9leGFtcGxlLm9yZy9jcmVkZW50aWFscy8zNzMxIiwKCQkidHlwZSI6CVsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwKCQkiY3JlZGVudGlhbFN1YmplY3QiOglbewoJCQkJImlkIjoJImRpZDppbzoweGIzMzVmNjUxZjkwZjc3OWM4NjU4ZTgyMzI1ODUwZGE1YjExYjA5YWMiCgkJCX1dLAoJCSJpc3N1ZXIiOgl7CgkJCSJpZCI6CSJkaWQ6aW86MHhkYzYyNzI0MDliNDhlMmQ5NTNmNDY1MzVhZjNhYzcwY2ZjYTg2ZmFiIgoJCX0sCgkJImlzc3VhbmNlRGF0ZSI6CSIyMDIwLTA4LTE5VDIxOjQxOjUwWiIKCX0KfQ.7vL1KgtsB0Qxy2VH0_3ecrHlPd81n6SHANzkBQIXUtjf-VY0VtYTvKcb7E0NPLwVR_05oDSXCWRNvrnq_UtM0A
Get ISS : did:io:0xdc6272409b48e2d953f46535af3ac70cfca86fab
Get Private Json : {
        "@context":     ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "id":   "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject":    [{
                        "id":   "did:io:0xb335f651f90f779c8658e82325850da5b11b09ac"
                }],
        "issuer":       {
                "id":   "did:io:0xdc6272409b48e2d953f46535af3ac70cfca86fab"
        },
        "issuanceDate": "2020-08-19T21:41:50Z"
}
Get Subject ID : did:io:0xb335f651f90f779c8658e82325850da5b11b09ac
Success to JWT [JWS] Verify
```











