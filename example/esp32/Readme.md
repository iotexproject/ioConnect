# DIDs API Examples

This directory contains simple examples demonstrating DIDs、JOSE、Device Register API.

Each example, contains README.md file with mode detailed informations about that particular example.

Examples:

- DIDs ：This example shows how to use the API provided by ioConnect SDK. Use ioConnect SDK to generate did, diddoc, VC, etc. for embedded devices.
- Device Register ：This example shows how to use the API provided by the ioConnect SDK Device Register component to register an ESP32-based embedded device to IoTeX Web. The entire registration process relies on DID and JOSE protocols. For details, please refer to the DIDs example.



DID Standard Document：

[Decentralized Identifiers (DIDs) v1.0 (w3c.github.io)](https://w3c.github.io/did-core/)

JOSE Standard Document：

[RFC 7517 - JSON Web Key (JWK) (ietf.org)](https://datatracker.ietf.org/doc/html/rfc7517)

[RFC 7515 - JSON Web Signature (JWS) (ietf.org)](https://datatracker.ietf.org/doc/html/rfc7515)

[RFC 7516 - JSON Web Encryption (JWE) (ietf.org)](https://datatracker.ietf.org/doc/rfc7516/)

[RFC 7519: JSON Web Token (JWT) (rfc-editor.org)](https://www.rfc-editor.org/rfc/rfc7519)

Other references:

[DIDComm](https://didcomm.org/book/v2/)



# Hardware Required

This example can be run on any commonly available ESP32S3 development board.



## Build and Flash

Build the project and flash it to the board, then run monitor tool to view serial output:

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for full steps to configure and use ESP-IDF to build projects.

