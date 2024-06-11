

# How to Generate a DID Document Using ioConnectSDK

​		A DIDDoc is a set of data describing the [DID subject](https://www.w3.org/TR/did-core/#dfn-did-subjects), including mechanisms, such as cryptographic public keys, that the [DID subject](https://www.w3.org/TR/did-core/#dfn-did-subjects) or a [DID delegate](https://www.w3.org/TR/did-core/#dfn-did-delegate) can use to [authenticate](https://www.w3.org/TR/did-core/#dfn-authenticated) itself and prove its association with the [DID](https://www.w3.org/TR/did-core/#dfn-decentralized-identifiers). A DID document might have one or more different [representations](https://www.w3.org/TR/did-core/#dfn-representations)



## Core properties

### DID Documentproerties

| Property               | Required | Value constraints                                            |
| ---------------------- | -------- | ------------------------------------------------------------ |
| `id`                   | yes      | A [string](https://infra.spec.whatwg.org/#string) that conforms to the rules |
| `alsoKnownAs`          | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of [strings](https://infra.spec.whatwg.org/#string) that conform to the rules of [[RFC3986](https://w3c.github.io/did-core/#bib-rfc3986)] for [URIs](https://w3c.github.io/did-core/#dfn-uri). |
| `controller`           | no       | A [string](https://infra.spec.whatwg.org/#string) or a [set](https://infra.spec.whatwg.org/#ordered-set) of [strings](https://infra.spec.whatwg.org/#string) that conform to the rules |
| `verificationMethod`   | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of [Verification Method](https://w3c.github.io/did-core/#dfn-verification-method) [maps](https://infra.spec.whatwg.org/#ordered-map) that conform to the rules in [Verification Method properties](https://w3c.github.io/did-core/#verification-method-properties). |
| `authentication`       | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of either [Verification Method](https://w3c.github.io/did-core/#dfn-verification-method) [maps](https://infra.spec.whatwg.org/#ordered-map) that conform to the rules in [Verification Method properties](https://w3c.github.io/did-core/#verification-method-properties)) or [strings](https://infra.spec.whatwg.org/#string) that conform to the rules |
| `assertionMethod`      | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of either [Verification Method](https://w3c.github.io/did-core/#dfn-verification-method) [maps](https://infra.spec.whatwg.org/#ordered-map) that conform to the rules in [Verification Method properties](https://w3c.github.io/did-core/#verification-method-properties)) or [strings](https://infra.spec.whatwg.org/#string) that conform to the rules |
| `keyAgreement`         | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of either [Verification Method](https://w3c.github.io/did-core/#dfn-verification-method) [maps](https://infra.spec.whatwg.org/#ordered-map) that conform to the rules in [Verification Method properties](https://w3c.github.io/did-core/#verification-method-properties)) or [strings](https://infra.spec.whatwg.org/#string) that conform to the rules |
| `capabilityInvocation` | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of either [Verification Method](https://w3c.github.io/did-core/#dfn-verification-method) [maps](https://infra.spec.whatwg.org/#ordered-map) that conform to the rules in [Verification Method properties](https://w3c.github.io/did-core/#verification-method-properties)) or [strings](https://infra.spec.whatwg.org/#string) that conform to the rules |
| `capabilityDelegation` | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of either [Verification Method](https://w3c.github.io/did-core/#dfn-verification-method) [maps](https://infra.spec.whatwg.org/#ordered-map) that conform to the rules in [Verification Method properties](https://w3c.github.io/did-core/#verification-method-properties)) or [strings](https://infra.spec.whatwg.org/#string) that conform to the rules |
| `service`              | no       | A [set](https://infra.spec.whatwg.org/#ordered-set) of [Service Endpoint](https://w3c.github.io/did-core/#dfn-service-endpoints) [maps](https://infra.spec.whatwg.org/#ordered-map) that conform to the rules in [Service properties](https://w3c.github.io/did-core/#service-properties). |

### Verification Method properties

| Property             | Required | Value constraints                                            |
| -------------------- | -------- | ------------------------------------------------------------ |
| `id`                 | yes      | A [string](https://infra.spec.whatwg.org/#string) that conforms to the rules in [3.2 DID URL Syntax](https://w3c.github.io/did-core/#did-url-syntax). |
| `conroller`          | yes      | A [string](https://infra.spec.whatwg.org/#string) that conforms to the rules in [3.1 DID Syntax](https://w3c.github.io/did-core/#did-syntax). |
| `type`               | yes      | A [string](https://infra.spec.whatwg.org/#string).           |
| `publicKeyJwk`       | no       | A [map](https://infra.spec.whatwg.org/#maps) representing a JSON Web Key that conforms to [[RFC7517](https://w3c.github.io/did-core/#bib-rfc7517)]. See [definition of publicKeyJwk](https://w3c.github.io/did-core/#dfn-publickeyjwk) for additional constraints. |
| `publicKeyMultibase` | no       | A [string](https://infra.spec.whatwg.org/#string) that conforms to a [[MULTIBASE](https://w3c.github.io/did-core/#bib-multibase)] encoded public key. |

### Service properties

| Property          | Required? | Value constraints                                            |
| ----------------- | --------- | ------------------------------------------------------------ |
| `id`              | yes       | A [string](https://infra.spec.whatwg.org/#string) that conforms to the rules of [[RFC3986](https://w3c.github.io/did-core/#bib-rfc3986)] for [URIs](https://w3c.github.io/did-core/#dfn-uri). |
| `type`            | yes       | A [string](https://infra.spec.whatwg.org/#string) or a [set](https://infra.spec.whatwg.org/#ordered-set) of [strings](https://infra.spec.whatwg.org/#string). |
| `serviceEndpoint` | yes       | A [string](https://infra.spec.whatwg.org/#string) that conforms to the rules of [[RFC3986](https://w3c.github.io/did-core/#bib-rfc3986)] for [URIs](https://w3c.github.io/did-core/#dfn-uri), a [map](https://infra.spec.whatwg.org/#string), or a [set](https://infra.spec.whatwg.org/#ordered-set) composed of a one or more [strings](https://infra.spec.whatwg.org/#string) that conform to the rules of [[RFC3986](https://w3c.github.io/did-core/#bib-rfc3986)] for [URIs](https://w3c.github.io/did-core/#dfn-uri) and/or [maps](https://infra.spec.whatwg.org/#string). |



## Definition

### enum VerificationMethod_Purpose

```c
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
```



### enum VerificationMethod_Type

```c
enum VerificationMethod_Type {
  VM_TYPE_DIDURL,
  VM_TYPE_RELATIVEDIDURL,
  VM_TYPE_MAP,
};
```



### enum ServiceEndpoint_type

```c
enum ServiceEndpoint_type {
  SERVICE_ENDPOINT_TYPE_URI,
  SERVICE_ENDPOINT_TYPE_MAP,
};
```



## API

```c
// Create a diddoc handle.
// Params : None
// Return [DIDDoc *] : a diddoc handle if successful, or NULL if failed.

DIDDoc* iotex_diddoc_new(void)
```



```c
// Destroy a diddoc.
// Params [DIDDoc *] : a diddoc handle from ‘iotex_diddoc_new’.
// Return : None.

void iotex_diddoc_destroy(DIDDoc *doc)
```



```c
// Create a VerificationMethod handle.
// Params [DIDDoc *] : a diddoc handle from ‘iotex_diddoc_new’.
// Params [enum VerificationMethod_Purpose] : Purpose of VerificationMethod. See Definition.
// Params [enum VerificationMethod_Type] : Type of VerificationMethod. See Definition.
// Return [DIDDoc_VerificationMethod*] : a VerificationMethod handle if successful, or NULL if failed.

DIDDoc_VerificationMethod* iotex_diddoc_verification_method_new(DIDDoc* diddoc, enum VerificationMethod_Purpose purpose, enum VerificationMethod_Type type)
```



```c
// Create a VerificationMethod Map handle.
// Params : None
// Return [VerificationMethod_Map] : a VerificationMethod Map handle if successful, or NULL if failed.

VerificationMethod_Map iotex_diddoc_verification_method_map_new(void)
```



```c
// Setting the VerificationMethod_Map value.
// Params [VerificationMethod_Map] : a VerificationMethod_Map handle from ‘iotex_diddoc_verification_method_map_new’.
// Params [build_type] : Construction Type.
//			IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID
//			IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE
//			IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON 
//			IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK 
//			IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_MULTIBASE
//			IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_BASE58   
// Params [void *] : value.
// Return [did_status_t] : The result of function execution.

did_status_t iotex_diddoc_verification_method_map_set(VerificationMethod_Map map, unsigned int build_type, void *value)
```



```c
// Setting the VerificationMethod value.
// Params [DIDDoc_VerificationMethod *] : a VerificationMethod handle from ‘iotex_diddoc_verification_method_new’.
// Params [enum VerificationMethod_Type] : Type of VerificationMethod. See Definition.  
// Params [void *] : value.
// Return [did_status_t] : The result of function execution.

did_status_t iotex_diddoc_verification_method_set(DIDDoc_VerificationMethod *vm, enum VerificationMethod_Type type, void *value)
```



```c
// Setting the proerty of diddoc.
// Params [DIDDoc *] : a diddoc handle from ‘iotex_diddoc_new’.
// Params [build_type] : Construction Type.  
//			IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT
//			IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID
//			IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ALSO_KNOWN_AS 
//			IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTROLLER 
//			IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_SERVICE
//			IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_PROPERTY 
// Params [name] : name of property, all except IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_PROPERTY will be ignored.
// Params [value] : value of property.
// Return [did_status_t] : The result of function execution.

did_status_t iotex_diddoc_property_set(DIDDoc *diddoc, unsigned int build_type, char *name, void *value);
```



```c
// Create a Service handle.
// Params : None.  
// Return [DIDDoc_Service *] : a DIDDoc_Service handle if successful, or NULL if failed.

DIDDoc_Service* iotex_diddoc_service_new(void)
```



```c
// Setting the DIDDoc_Service value.
// Params [DIDDoc_Service *] : a DIDDoc_Service handle from ‘iotex_diddoc_service_new’.
// Params [build_type] : Construction Type.  
//			IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ID
//			IOTEX_DIDDOC_BUILD_SERVICE_TYPE_TYPE
//			IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ENDPOINT 
// Params [value] : value of Service.
// Return [did_status_t] : The result of function execution.

did_status_t iotex_diddoc_service_set(DIDDoc_Service* Service, unsigned int build_type, void *value)
```



```c
// Create a Service Endpoint handle.
// Params [enum ServiceEndpoint_type] : Type of ServiceEndpoint. See Definition.  
// Return [DIDDoc_ServiceEndpoint *] : a ServiceEndpoint handle if successful, or NULL if failed.

DIDDoc_ServiceEndpoint* iotex_diddoc_service_endpoint_new(enum ServiceEndpoint_type type)
```



```c
// Setting the ServiceEndpoint value.
// Params [DIDDoc_ServiceEndpoint *] : a ServiceEndpoint handle from ‘iotex_diddoc_service_endpoint_new’.
// Params [enum ServiceEndpoint_type] : Type of ServiceEndpoint. See Definition.  .  
//			IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ID
//			IOTEX_DIDDOC_BUILD_SERVICE_TYPE_TYPE
//			IOTEX_DIDDOC_BUILD_SERVICE_TYPE_ENDPOINT 
// Params [value] : value of Service.
// Return [did_status_t] : The result of function execution.

did_status_t iotex_diddoc_service_endpoint_set(DIDDoc_ServiceEndpoint* ServiceEndpoint, enum ServiceEndpoint_type type, void *value)
```



```c
// Output diddoc.
// Params [DIDDoc *] : a diddoc handle from ‘iotex_diddoc_new’.
// Params [format] : If true, the output is formatted, if false the output is unformatted.
// Return [char *] : a output of the diddoc if successful, or NULL if failed.

char *iotex_diddoc_serialize(DIDDoc *diddoc, bool format)
```



## Example

```c
did_status_t did_status;

DIDDoc* peerDIDDoc = iotex_diddoc_new();
if (NULL == peerDIDDoc) {
	printf("Failed to new a peerDIDDoc\n");
	goto exit;
}

did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");

did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");

did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, peerSignDID);
if (DID_SUCCESS != did_status) {
	printf("iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
	goto exit; 
}

// Make a verification method [type : authentication]
DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);    
if (NULL == vm_authentication) {
	printf("Failed to iotex_diddoc_verification_method_new()\n");
}

did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, peerSignKID);
if (DID_SUCCESS != did_status) {
	printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
    goto exit; 
}

VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerSignKID);
did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerSignJWK));

// Make a verification method [type : key agreement]
DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);    
if (NULL == vm_agreement) {
	printf("Failed to iotex_diddoc_verification_method_new()\n");
}

did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, peerKAKID);
if (DID_SUCCESS != did_status) {
	printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
	goto exit; 
} 

VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerKAKID);
did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerKAJWK));

DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);

did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

char *peerDIDDoc_Serialize = iotex_diddoc_serialize(peerDIDDoc, true);
if (peerDIDDoc_Serialize)
	printf("DIDdoc : \n%s\n", peerDIDDoc_Serialize);

iotex_diddoc_destroy(peerDIDDoc);
```



## output

```
DIDdoc :
{
        "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
        "id":   "did:io:0x6c5ea73f0824f366665a6618dc140f37652daf96",
        "authentication":       ["did:io:0x6c5ea73f0824f366665a6618dc140f37652daf96#Key-p256-2147483618"],
        "keyAgreement": ["did:io:0xcbe493edde55bedb53a274524758bf46782604ab#Key-p256-2147483619"],
        "verificationMethod":   [{
                        "id":   "did:io:0x6c5ea73f0824f366665a6618dc140f37652daf96#Key-p256-2147483618",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0x6c5ea73f0824f366665a6618dc140f37652daf96",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "LkIWOM-NEeeN0gIU0akYcVs5zIK8yIqWnLvrs2ALNd0",
                                "y":    "-eQUT37pvLIeFx5cr5YJMyp3w4rYaD-hhVjtzsKnbDQ",
                                "kty":  "EC",
                                "kid":  "Key-p256-2147483618"
                        }
                }, {
                        "id":   "did:io:0xcbe493edde55bedb53a274524758bf46782604ab#Key-p256-2147483619",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0x6c5ea73f0824f366665a6618dc140f37652daf96",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "AToMUwNqP6PYk_PDp9tDHr3blWpxBxyHsTcFNcMoPNE",
                                "y":    "E-s-PM7K_OTj8CDi7Lm3Z-eqIt6Ymr96atoRw-BlgO4",
                                "kty":  "EC",
                                "kid":  "Key-p256-2147483619"
                        }
                }]
}
```











