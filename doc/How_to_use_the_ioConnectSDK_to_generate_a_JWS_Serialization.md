

# How to use the ioConnect SDK to generate a JWS Serialization 

JSON Web Signature (JWS) represents content secured with digital signatures or Message Authentication Codes (MACs) using JSON-based [RFC7159] data structures.  The JWS cryptographic mechanisms provide integrity protection for an arbitrary sequence of octets.  Two closely related serializations for JWSs are defined.  The JWS Compact Serialization is a compact, URL-safe representation intended for space-constrained environments such as HTTP Authorization headers and URI query parameters.  The JWS JSON Serialization represents JWSs as JSON objects and enables multiple signatures and/or MACs to be applied to the same content.  Both share the same cryptographic underpinnings.



## JSON Web Signature (JWS) Overview

JWS represents digitally signed or MACed content using JSON data structures and base64url encoding. These JSON data structures MAY contain whitespace and/or line breaks before or after any JSON values or structural characters, in accordance with Section 2 of RFC 7159 [RFC7159]. A JWS represents these logical values :

- JOSE Header
- JWS Payload
- JWS Signature

For a JWS, the JOSE Header members are the union of the members of these values：

- JWS Protected Header
- JWS Unprotected Header

This document defines two serializations for JWSs: a compact, URL- safe serialization called the JWS Compact Serialization and a JSON serialization called the JWS JSON Serialization. In both serializations, the JWS Protected Header, JWS Payload, and JWS Signature are base64url encoded, since JSON lacks a way to directly represent arbitrary octet sequences.

### JWS Compact Serialization Overview

In the JWS Compact Serialization, no JWS Unprotected Header is used. In this case, the JOSE Header and the JWS Protected Header are the same.

In the JWS Compact Serialization, a JWS is represented as the concatenation:
$$
BASE64URL(UTF8(JWS Protected Header)) || ’.’ || BASE64URL(JWS Payload) || ’.’ || BASE64URL(JWS Signature)
$$

### JWS JSON Serialization Overview

In the JWS JSON Serialization, one or both of the JWS Protected Header and JWS Unprotected Header MUST be present. In this case, the members of the JOSE Header are the union of the members of the JWS Protected Header and the JWS Unprotected Header values that are present.

In the JWS JSON Serialization, a JWS is represented as a JSON object containing some or all of these four members:

- "protected", with the value BASE64URL(UTF8(JWS Protected Header)) 
- "header", with the value JWS Unprotected Header 
- "payload", with the value BASE64URL(JWS Payload) 
- "signature", with the value BASE64URL(JWS Signature)

The three base64url-encoded result strings and the JWS Unprotected Header value are represented as members within a JSON object. The inclusion of some of these values is OPTIONAL. The JWS JSON Serialization can also represent multiple signature and/or MAC values, rather than just one. 



## 

## Standards and Protocols

- **Internet Engineering Task Force (IETF)**:
- ([RFC 7515 - JSON Web Signature (JWS) (ietf.org)](https://datatracker.ietf.org/doc/html/rfc7515))



## API

```c
// Generate a JWS Compact serialization.
// Params [enum JWAlogrithm] : JWA supported algorithms. See Definition.
// Params [plaintext] : Plaintext data.
// Params [plaintext_size] : Size of plaintext data.
// Params [JWK *] : The JWK pointer to be used.
// Return [char *] : a JWS Compact serialization if successful, or NULL if failed.

char *iotex_jws_compact_serialize(enum JWAlogrithm alg, char *plaintext, size_t plaintext_size, JWK *jwk);
```



```c
// Multi-part JWS operations. First Step, create a jws handle.
// Params [plaintext] : Plaintext data.
// Params [plaintext_size] : Size of plaintext data.
// Return [JWK *] : a JWK handle if successful, or NULL if failed.

jws_handle_t iotex_jws_general_json_serialize_init(char *plaintext, size_t plaintext_size);
```



```c
// Multi-part JWS operations. Update the "kid", jwk, alg to the JWS.
// Params [jws_handle_t] : a JWS handle from function "iotex_jws_general_json_serialize_init".
// Params [enum JWAlogrithm] : JWA supported algorithms. See Definition.
// Params [kid] : If you need to include a "header" field in the JWS, set it, otherwise it can be NULL.
// Params [JWK *] : The JWK pointer to be used.
// Return [jose_status_t] : The return status of this function.

jose_status_t iotex_jws_general_json_serialize_update(jws_handle_t handle, enum JWAlogrithm alg, char *kid, JWK *jwk);
```



```c
// Multi-part JWS operations. Output.
// Params [jws_handle_t] : a JWS handle from function "iotex_jws_general_json_serialize_init".
// Params [format] : Generate a formatted information if true, otherwise unformatted information is generated.
// Return [char *] : a JWS Serialization if successful, or NULL if failed.

char *iotex_jws_general_json_serialize_finish(jws_handle_t handle, bool format);
```



```c
// Generate a JWS Flattened serialization.
// Params [enum JWAlogrithm] : JWA supported algorithms. See Definition.
// Params [plaintext] : Plaintext data.
// Params [plaintext_size] : Size of plaintext data.
// Params [kid] : If you need to include a "header" field in the JWS, set it, otherwise it can be NULL.
// Params [enum JWS_USAGE] : The purpose of this JWS, which determines the contents of the "typ" field. See Definition.
// Params [JWK *] : The JWK pointer to be used.
// Return [char *] : a JWS Flattened serialization if successful, or NULL if failed.

char *iotex_jws_flattened_json_serialize(enum JWAlogrithm alg, char *plaintext, size_t plaintext_size, char *kid, enum JWS_USAGE usage, JWK *jwk, bool format);
```



```c
// Verify a JWS serialization.
// Params [enum JWAlogrithm] : JWA supported algorithms. See Definition.
// Params [jws_msg] : A verified JWS message.
// Params [JWK *] : The JWK pointer to be used.
// Return [bool] : true: verification passed, false: verification failed.

bool iotex_jws_compact_verify(enum JWAlogrithm alg, char *jws_msg, JWK *jwk);
```



## Definition

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



### enum JWS_USAGE

```c
enum JWS_USAGE {
    JWS_USAGE_DIDCOMM,
    JWS_USAGE_JWT,
    JWS_USAGE_JSON,
    JWS_USAGE_COMPACT,
};
```



## Example

```c
char *jws_compact = iotex_jws_compact_serialize(ES256, "This is a JWS Test", strlen("This is a JWS Test"), jwk);
if (jws_compact)
    printf("JWS Compact Serialize : \n%s\n", jws_compact);

jws_handle_t handle = iotex_jws_general_json_serialize_init("This is a JWS Test", strlen("This is a JWS Test"));
jose_status_t did_status = iotex_jws_general_json_serialize_update(handle, ES256, did_key, jwk);    
char *jws_general_json = iotex_jws_general_json_serialize_finish(handle, true);
if (jws_general_json)
    printf("JWS General JSON Serialize : \n%s\n", jws_general_json);

char *jws_flattened_json = iotex_jws_flattened_json_serialize(ES256, "This is a JWS Test", strlen("This is a JWS Test"), did_key, JWS_USAGE_JSON, jwk, true);
if (jws_flattened_json)
    printf("JWS Flattened JSON Serialize : \n%s\n", jws_flattened_json);

if (iotex_jws_compact_verify(ES256, jws_compact, jwk))
    printf("Success to JWS Compact verify\n");
else
    printf("Fail to JWS Compact verify\n");
```



## output

```
JWS Compact Serialize :
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
JWS General JSON Serialize :
{
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header":
       {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature":
       "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
        lSApmWQxfKTUJqPP3-Kg6NU1Q"
}
JWS Flattened JSON Serialize :
{
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header":
       {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature":
       "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
        lSApmWQxfKTUJqPP3-Kg6NU1Q"
}
Success to JWS Compact verify
```











