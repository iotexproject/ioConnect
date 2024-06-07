| Supported Targets | ESP32S3 |
| ----------------- | ------- |



# DIDs Example

(See the README.md file in the upper level 'examples' directory for more information about examples.)

This example shows how to use the API of DIDs、JOSE component of ioConnect for connecting to implement W3C standards.



## What this example does

- Generate two JWKs.
  - A JWK with a lifetime of persist for signing and verification.
  - A JWK with a lifetime of volatile for key exchange.
- Generate the corresponding DID based on JWK and use the "io" method.
- Generate the DIDdoc.
- Generate a verifiable credential.
- Generate a JWT by signing the VC generated.
- Verify the JWT.
- Generate a DIDcomm Message.
- Decrypt the DIDComm Message.



## How to use example

### Build and Flash

Build the project and flash it to the board, then run the monitor tool to view the serial output:

Run `idf.py -p PORT flash monitor` to build, flash and monitor the project.

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for all the steps to configure and use the ESP-IDF to build projects.

* [ESP-IDF Getting Started Guide on ESP32](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
* [ESP-IDF Getting Started Guide on ESP32-S2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/get-started/index.html)
* [ESP-IDF Getting Started Guide on ESP32-C3](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/get-started/index.html)

## Example Output
Note that the output, in particular the order of the output, may vary depending on the environment.

```
My Sign DID :                   did:io:0x4af1fb74424551c3bbf1766740570a19ca8af2fd
My Key Agreement DID :          did:io:0xe6a16d5473e6a60acc505b3450814f6750388e41
Peer DID :                      did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8
Peer Key Agreement DID :        did:io:0x5d28cd35ea7186940ba7d7ea9f5f95212b389063
DIDdoc :
{
        "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
        "id":   "did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8",
        "authentication":       ["did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8#Key-p256-2147483618"],
        "keyAgreement": ["did:io:0x5d28cd35ea7186940ba7d7ea9f5f95212b389063#Key-p256-2147483619"],
        "verificationMethod":   [{
                        "id":   "did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8#Key-p256-2147483618",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "OIs1PeU2RR9Yt_Vuwir2MC9uu-rMDbV35No3Qo24lv4",
                                "y":    "8rARoIaNHlAjpKnhjk5qPRPzFDeu9XEuIN5OmKQLPM8",
                                "kty":  "EC",
                                "kid":  "Key-p256-2147483618"
                        }
                }, {
                        "id":   "did:io:0x5d28cd35ea7186940ba7d7ea9f5f95212b389063#Key-p256-2147483619",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "gvAetnhhQW_RHtpfWiaxxWYQHda59doyqOtCSwHjss0",
                                "y":    "2SG_0GwYU2RqqtV_1A651Q2YMUb-qIH3aaoGUwOOvXY",
                                "kty":  "EC",
                                "kid":  "Key-p256-2147483619"
                        }
                }]
}
VC :
{
        "@context":     ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "id":   "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject":    [{
                        "id":   "did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8"
                }],
        "issuer":       {
                "id":   "did:io:0x4af1fb74424551c3bbf1766740570a19ca8af2fd"
        },
        "issuanceDate": "2020-08-19T21:41:50Z"
}
JWT[JWS]:
eyJhbGciOiJFUzI1NiJ9.ewoJImlzcyI6CSJkaWQ6aW86MHg0YWYxZmI3NDQyNDU1MWMzYmJmMTc2Njc0MDU3MGExOWNhOGFmMmZkIiwKCSJ2cCI6CXsKCQkiQGNvbnRleHQiOglbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sCgkJImlkIjoJImh0dHA6Ly9leGFtcGxlLm9yZy9jcmVkZW50aWFscy8zNzMxIiwKCQkidHlwZSI6CVsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwKCQkiY3JlZGVudGlhbFN1YmplY3QiOglbewoJCQkJImlkIjoJImRpZDppbzoweGNiNDQzZjQyMGNiMDFhZjczOTJiMGI4OWUxZGY4YjEyMGM5OGVlZTgiCgkJCX1dLAoJCSJpc3N1ZXIiOgl7CgkJCSJpZCI6CSJkaWQ6aW86MHg0YWYxZmI3NDQyNDU1MWMzYmJmMTc2Njc0MDU3MGExOWNhOGFmMmZkIgoJCX0sCgkJImlzc3VhbmNlRGF0ZSI6CSIyMDIwLTA4LTE5VDIxOjQxOjUwWiIKCX0KfQ.4z5Y5b7F8LPupiCgYcbmGiDvGob6Z-Qua6MgLqjtyYPMn5EW4t1Gd9t-B1zVs2a3uqJTmd4L2l9k43B0YCea3w
Get ISS : did:io:0x4af1fb74424551c3bbf1766740570a19ca8af2fd
Get Private Json : {
        "@context":     ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "id":   "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject":    [{
                        "id":   "did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8"
                }],
        "issuer":       {
                "id":   "did:io:0x4af1fb74424551c3bbf1766740570a19ca8af2fd"
        },
        "issuanceDate": "2020-08-19T21:41:50Z"
}
Get Subject ID : did:io:0xcb443f420cb01af7392b0b89e1df8b120c98eee8
Success to JWT [JWS] Verify
JWE JSON Serialize : 
{
        "ciphertext":   "7IBNfODOD36nLC-3t0EulFb2",
        "protected":    "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6aW86MHhjYjQ0M2Y0MjBjYjAxYWY3MzkyYjBiODllMWRmOGIxMjBjOThlZWU4IiwiYXB1IjoiWkdsa09tbHZPakI0WTJJME5ETm1OREl3WTJJd01XRm1Oek01TW1Jd1lqZzVaVEZrWmpoaU1USXdZems0WldWbE9BIiwiYXB2IjoiX0FpVHdYQy1nV2VZRXBvc1BmaklUOU5ZT2p6a2pXc2wxeEtOSEhYaXZIWSIsImVwayI6eyJjcnYiOiJQLTI1NiIsIngiOiJ6NnVLd1hOYzIzZ0NvSl9KV19YYXJZOFNDTGhHbUdQZ3UzWnJjVHU5Yk5JIiwieSI6IjVCRnp5WHpNU2FRTTRiT3pCVjBXT1o3d3FINDVxRzZpRE5YLXNHdGZsekEiLCJrdHkiOiJFQyIsImtpZCI6IktleS1wMjU2LTIxNDc0ODM2MjEifX0",
        "recipients":   [{
                        "header":       {
                                "kid":  "did:io:0xe6a16d5473e6a60acc505b3450814f6750388e41#Key-p256-2147483617"
                        },
                        "encrypted_key":        "3uK8hZt1OVWzYA5tRG3egnViqkV4qsNRuRjdVJ6sDCp_bWum7QxWfcLpyHMfOSnK"
                }],
        "tag":  "-PNbo4TrlDC9GFkH5c6LGA",
        "iv":   "7XjWMsfVnocB7KRwsQ"
}
JWE Decrypted Plaintext : 
This is a JWE Test
```


## Troubleshooting

For any technical queries, please open an [issue]([Issues · machinefi/ioConnect (github.com)](https://github.com/machinefi/ioConnect/issues)) on GitHub. We will get back to you soon.
