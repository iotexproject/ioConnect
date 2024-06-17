# Communicating with Sprout



In the file structure of the Platform Adaptation Layer (PAL), the SDK mainly implements methods for connecting to IoTeX decentralized network nodes. For example, the `DeviceRegister` component provides a method for terminal devices to register with the IoTeX Wallet, and the `Sprout` component allows easy communication with Sprout.



# Process

This section demonstrates the usage of ioConnect and the communication process with Sprout through the following Proof of Concept (POC):



### Step.0  ioConnect SDK initialization

```c++
iotex_ioconnect_sdk_init();
```



### Step.1  Get Server's DIDDoc

```c
DIDDoc *DIDDoc_Server = iotex_pal_sprout_server_diddoc_get();
```

The server’s DIDDoc is obtained by calling the Sprout component’s API: `iotex_pal_sprout_server_diddoc_get()`. Upon successful return of this method, the following similar information will be obtained:

```json
Server DIDDoc :
{
        "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
        "id":   "did:io:0xda0f85098a7e88b379f8fcac742c99561137780f",
        "authentication":       ["did:io:0xda0f85098a7e88b379f8fcac742c99561137780f#Key-p256-2147483616"],
        "keyAgreement": ["did:io:0xaefe2f283b262978a1cabc483410593d62c9c732#Key-p256-2147483617"],
        "verificationMethod":   [{
                        "id":   "did:io:0xaefe2f283b262978a1cabc483410593d62c9c732#Key-p256-2147483617",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xda0f85098a7e88b379f8fcac742c99561137780f",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "xaKC13yoR2Q6FSF6mrm027-onSs9qud4OApuIE6eFd4",
                                "y":    "PQk3EoMlKYf9FqorTUN8slXpNSpHyhZdxDBJ9dJmnzE",
                                "d":    "",
                                "kty":  "EC",
                                "kid":  "Key-p256-2147483617"
                        }
                }, {
                        "id":   "did:io:0xda0f85098a7e88b379f8fcac742c99561137780f#Key-p256-2147483616",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xda0f85098a7e88b379f8fcac742c99561137780f",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "ZxArQGShiyq2Mfdh10V75zsz68Q94YxnW_CeJnJo1Ms",
                                "y":    "7GLUKpiFI0sOGloNSKXQDwovKMLDGe7hrQqBEaWW66k",
                                "d":    "",
                                "kty":  "EC",
                                "kid":  "Key-p256-2147483616"
                        }
                }]
}
```

#### Step.1.1 Parsing the Server’s DIDDoc and Obtaining KeyAgreement KID

```c
unsigned int vm_num = iotex_diddoc_verification_method_get_num(DIDDoc_Server, VM_PURPOSE_KEY_AGREEMENT);

VerificationMethod_Info *vm_info = iotex_diddoc_verification_method_get(DIDDoc_Server, VM_PURPOSE_KEY_AGREEMENT, vm_num - 1);   

char *server_ka_kid = vm_info->id;  
```

The code above demonstrates how to parse the server’s DIDDoc to obtain the KeyID for KeyAgreement. Upon successful parsing, the following similar information will be obtained:

```c
Server KA KID : did:io:0xaefe2f283b262978a1cabc483410593d62c9c732#Key-p256-2147483617
```



### Step.2  Generate the JWK for the device

```c
unsigned int key_id = 1;   

JWK *signjwk = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,

               IOTEX_JWK_LIFETIME_PERSISTENT,

               PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,

               PSA_ALG_ECDSA(PSA_ALG_SHA_256),

               &key_id);   


unsigned int kakey_id = 2;   

JWK *kajwk = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,

               IOTEX_JWK_LIFETIME_PERSISTENT,

               PSA_KEY_USAGE_DERIVE,

               PSA_ALG_ECDH,

               &kakey_id);   
```

`iotex_jwk_generate()` is an API provided by the JWK component, used to generate keys for different purposes for the device. Upon successful generation, the following similar information will be obtained:

```json
JWK[Sign] :
{
        "crv":  "secp256k1",
        "x":    "KAkqUSARxKvyrfkykUH9fl5Ef6AbcaoEWQgi8IwFdIo",
        "y":    "dmlXLytvKgIVH4hgPP2Tzlp6dJbq5KWtluiX1U1v9o0",
        "kty":  "EC",
        "kid":  "Key-secp256k1-1"
}
JWK[KA] :
{
        "crv":  "P-256",
        "x":    "WIbBzvEz-6beOyvZtVmtN9J1EvPlgKUPDTPZy3kJJnk",
        "y":    "OvsnblaTwctIM2tP3pu8kh2RxpXxIwwtNceM4Z9iKcI",
        "kty":  "EC",
        "kid":  "Key-p256-2"
}
```



### Step.3  Generate DID based on JWK

```c
char *myDID = iotex_did_generate("io", signjwk);

char *myKA_Kid = iotex_jwk_generate_kid("io", kajwk);
```

`iotex_did_generate()` is a method provided by the DID component, with “io” being the method for generating IoTeX registered DIDs. The generated DID will be similar to the following information:

```c
did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73
```



### Step.4  Generate DIDDoc based on DID

```c
DIDDoc* diddoc = iotex_diddoc_new();

iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");

iotex_diddoc_property_set(diddoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, myDID);

DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);    
iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, myMasterkid);

VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, myMasterkid);
iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, myDID);
iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(signjwk));  

DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);    

iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, myKA_Kid);

VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, myKA_Kid);
iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, myDID);
iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(kajwk));

DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(diddoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);

iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

myDIDDoc = iotex_diddoc_serialize(diddoc, true);
```

The ioConnect SDK provides a set of `iotex_diddoc_***` methods for developers to easily construct a device’s DIDDoc. The successfully generated DIDDoc will be similar to the following information:

```json
{
        "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
        "id":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73",
        "authentication":       ["did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73#Key-secp256k1-1"],
        "keyAgreement": ["did:io:0xfab99326ce27d0d30b8609e6d4d748629242b077#Key-p256-2"],
        "verificationMethod":   [{
                        "id":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73#Key-secp256k1-1",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73",
                        "publicKeyJwk": {
                                "crv":  "secp256k1",
                                "x":    "KAkqUSARxKvyrfkykUH9fl5Ef6AbcaoEWQgi8IwFdIo",
                                "y":    "dmlXLytvKgIVH4hgPP2Tzlp6dJbq5KWtluiX1U1v9o0",
                                "kty":  "EC",
                                "kid":  "Key-secp256k1-1"
                        }
                }, {
                        "id":   "did:io:0xfab99326ce27d0d30b8609e6d4d748629242b077#Key-p256-2",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "WIbBzvEz-6beOyvZtVmtN9J1EvPlgKUPDTPZy3kJJnk",
                                "y":    "OvsnblaTwctIM2tP3pu8kh2RxpXxIwwtNceM4Z9iKcI",
                                "kty":  "EC",
                                "kid":  "Key-p256-2"
                        }
                }]
}
```



###  Step.5  Request Token from server

```c
iotex_pal_sprout_request_token(myDID, myKA_Kid);   
```

A token is requested from the server using the Sprout component’s method `iotex_pal_sprout_request_token`. Upon successful return, the ciphertext of the token will be similar to the following:

```c
{"ciphertext":"-Kjgcc2QoLWU9VFKy4hyOwsXsJYpAV8A_bAPrK8k2_DKltyOXMM6LtxJ2DoeeRFKJWu--c-exM5OWzCT1Uxy69Vt52Nq0ICMAWk0nZyb4iGQXSNGKhH-cbkZZBNnZ4jrOEqN2Pv_9MMAEc6CDRUmedvQGw31HmwfUui8x299Xbf0eHmMp9fiMjWTdnHCkoc4UA5p0n0gMz04OaBXU2nWu5jzNnSH8kEb9LwY90S01C2rHV47-BAGvJbEdPzeq8WqIUhEcZDAaYkx5falSuTbFjz7wBPgzVEIbhTppOIcWCnN7BMeIqc3tMsVZUE_KgVwUyyTbKCuPPDVNlufFwsZH_C4VKuX0PuxTEE83FQuIHw1c2MzvX1XMB9qa4ibbfyixp2UtNXi8RawoEUWd_0VqorEN5oyGwfEhdFA_eWO49v_ZZ6_APWyM6MyZpzq5HuePrON3Jdk1sYDqi18rt7_18IAJ6C1ZCGpUwTOnv97STISUJPBGtDauqiS5Aq_ZlZGbIy4BJ1IFG2CNYMiSQ2uZv3ymFVb9kvY2q1hYvm14aV7_lDdm_rKVcvV-593WLFrstkCEel5bBzBEafqXj3FE4s6tAe-jgG2TdR0_Ljm5PJ-fTfvMNjLK5BNJBHju_8keYSkXO-QwXJ_5KPtMwOKGLoFYeFRaVh1JvZO-9k1tXuoFjgW4sSmh_pc0o1x2FpVxMkDQxfEXcKm_VMYds9ujK0i1DEo6-aWzeV2iVqAv-n0TS1LSmgGBboT1sBpnvMLIyHzZleLdpAGUcUIJBHz4uRUwONZoa2VO_3NKJeimX9BfOmrFNEjYfUhQc0pAHSfzkm4VG2VFMpR0zpV3V-xgOrqKnHlLYBmEptDrAbxErDJnuVerSHc7efJPAF0VBjK6TGsZlKDqPBAfZMQhnNt91mD1vf1AxXgUb_vg2IanSDVWyX9pU1hmfZslwozoEa75NmcIwEn4rxaauA-UFqw_UecnJODQ3_7ED3qBmcB72HTpw","protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6aW86MHhkYTBmODUwOThhN2U4OGIzNzlmOGZjYWM3NDJjOTk1NjExMzc3ODBmIiwiYXB1IjoiWkdsa09tbHZPakI0WkdFd1pqZzFNRGs0WVRkbE9EaGlNemM1WmpobVkyRmpOelF5WXprNU5UWXhNVE0zTnpnd1pnIiwiYXB2IjoiZ1h1a3ZWYzJrM1doTHdmY0VxMGQ4MHNCdjdLMHhBbUF1R2ZFN3RjeVdIRSIsImVwayI6eyJjcnYiOiJQLTI1NiIsIngiOiJ2OXZUekhjZVBmU2NtdjRrbGZSZUdxV3hLclRBSUhyTzB2ck1hNTJ4LTJjIiwieSI6IjBYZ242eC0ya0JqTlhmeGNPMm1DVTliaDJYT3ZuMmowLTVhS1Q4QU9tRVEiLCJrdHkiOiJFQyIsImtpZCI6IktleS1wMjU2LTIxNDc0ODM2MTkifX0","recipients":[{"header":{"kid":"did:io:0xfab99326ce27d0d30b8609e6d4d748629242b077#Key-p256-2"},"encrypted_key":"invn8xTeoiV0v0EfAVpue33wD4Fz6VlXXehKqZeeQi7Z6QPEHVv2dQIiDqPSYvQR"}],"tag":"QwYLKDo03W3ujPkxRyMQXA","iv":"Rf1mQlr2RLdbjXvAZg"}
```

The plaintext obtained after decryption will be similar to the following:

```c
eyJhbGciOiJFUzI1NiJ9.ewoJImlzcyI6CSJkaWQ6aW86MHhkYTBmODUwOThhN2U4OGIzNzlmOGZjYWM3NDJjOTk1NjExMzc3ODBmIiwKCSJ2cCI6CXsKCQkiQGNvbnRleHQiOglbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sCgkJImlkIjoJImh0dHA6Ly9leGFtcGxlLm9yZy9jcmVkZW50aWFscy8zNzMxIiwKCQkidHlwZSI6CVsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwKCQkiY3JlZGVudGlhbFN1YmplY3QiOglbewoJCQkJImlkIjoJImRpZDppbzoweGJhODBiNzEwZjBjMjdjOGIzYjcyZGY2Mzg2MWUyZWNlYTljNWFhNzMiCgkJCX1dLAoJCSJpc3N1ZXIiOgl7CgkJCSJpZCI6CSJkaWQ6aW86MHhkYTBmODUwOThhN2U4OGIzNzlmOGZjYWM3NDJjOTk1NjExMzc3ODBmIgoJCX0sCgkJImlzc3VhbmNlRGF0ZSI6CSIyMDI0LTA1LTIxVDE0OjQ3OjQ4WiIKCX0KfQ.h04IPoKs01kc1o9R7SIYB0WW823h9cDoM5z0wR-ZlAEDrT6Zyr2l9WSWI_-MY0v_0xqZ2CQODRYtpYmk_G81Ww
```



### Step.6  Send a message to Sprout

#### Step.6.1  Create a Message

```c
cJSON *payload = cJSON_CreateObject();
cJSON_AddStringToObject(payload, "private_input", "14");
cJSON_AddStringToObject(payload, "public_input", "3.34");
cJSON_AddStringToObject(payload, "receipt_type", "Snark");
char *payload_serialize = cJSON_PrintUnformatted(payload);

cJSON *message = cJSON_CreateObject();
cJSON_AddNumberToObject(message, "projectID", SPROUT_PROJECT_ID);
cJSON_AddStringToObject(message, "projectVersion", "0.1");
cJSON_AddStringToObject(message, "data", payload_serialize);
char *message_serialize = cJSON_PrintUnformatted(payload);
```

The code demonstrates the process of constructing a message using JSON. The plaintext of the message will be similar to the following:

```json
{"projectID":21,"projectVersion":"0.1","data":"{\"private_input\":\"14\",\"public_input\":\"3.34\",\"receipt_type\":\"Snark\"}"}
```



#### Step.6.2  Send the Message

```c
char *recipients_kid[JOSE_JWE_RECIPIENTS_MAX] = {0};
recipients_kid[0] = server_ka_kid;

char *didcomm_payload = iotex_jwe_encrypt(payload_str, Ecdh1puA256kw, A256cbcHs512, myDID, signjwk, recipients_kid, false);

iotex_pal_sprout_send_message(didcomm_payload, myKA_Kid);
```

Using the KeyAgreement KID obtained from parsing the server’s DIDDoc, the ioConnect SDK encrypts the payload data using the `iotex_jwe_encrypt` method provided by the JWE component. Finally, the encrypted data is sent to Sprout using the `iotex_pal_sprout_send_message` method provided by the Sprout component.

### Step.7  Query the status of Message

```c
iotex_pal_sprout_msg_query(myKA_Kid);
```

The status of the message is queried from the server using the `iotex_pal_sprout_msg_query` method provided by the Sprout component. Upon successful return, the status will be similar to the following:

```json
{"messageID":"1c32fa20-411b-42c7-94c1-1244c3fc9a18","states":[{"state":"received","time":"2024-05-21T14:47:50.105185Z","comment":"","result":""},{"state":"packed","time":"2024-05-21T14:47:50.108577Z","comment":"","result":""}]}
```

