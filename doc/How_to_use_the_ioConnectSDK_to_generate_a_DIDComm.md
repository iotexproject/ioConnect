

# How to use the ioConnect SDK to generate a DIDComm 



## Purpose and Scope of DIDComm

The purpose of DIDComm Messaging is to provide a secure, private communication methodology built atop the decentralized design of [DIDs](https://www.w3.org/TR/did-core/).

It is the second half of this sentence, not the first, that makes DIDComm interesting. “Methodology” implies more than just a mechanism for individual messages, or even for a sequence of them. DIDComm Messaging defines how messages compose into the larger primitive of [application-level protocols](https://identity.foundation/didcomm-messaging/spec/#protocols) and workflows, while seamlessly retaining trust. “Built atop … DIDs” emphasizes DIDComm’s connection to the larger decentralized identity movement, with its many attendent virtues.

Of course, robust mechanisms for secure communication already exist. However, most rely on key registries, identity providers, certificate authorities, browser or app vendors, or similar centralizations. Many are for unstructured rich chat only — or enable value-add behaviors through proprietary extensions. Many also assume a single transport, making it difficult to use the same solution for human and machine conversations, online and offline, simplex and duplex, across a broad set of modalities. And because these limitations constantly matter, composability is limited — every pairing of human and machine for new purposes requires a new endpoint, a new API, and new trust. Workflows that span these boundaries are rare and difficult.

All of these factors perpetuate an asymmetry between institutions and ordinary people. The former maintain certificates and always-connected servers, and publish APIs under terms and conditions they dictate; the latter suffer with usernames and passwords, poor interoperability, and a Hobson’s choice between privacy and convenience.

DIDComm Messaging can fix these problems. Using DIDComm, individuals on semi-connected mobile devices become full peers of highly available web servers operated by IT experts. Registration is self-service, intermediaries require little trust, and terms and conditions can come from any party.

DIDComm Messaging enables higher-order protocols that inherit its security, privacy, decentralization, and transport independence. Examples include exchanging verifiable credentials, creating and maintaining relationships, buying and selling, scheduling events, negotiating contracts, voting, presenting tickets for travel, applying to employers or schools or banks, arranging healthcare, and playing games. Like web services atop HTTP, the possibilities are endless; unlike web services atop HTTP, many parties can participate without being clients of a central server, and they can use a mixture of connectivity models and technologies. And these protocols are composable into higher-order workflows without constantly reinventing the way trust and identity transfer across boundaries.



## Message Formats

### DIDComm Plaintext Messages

A DIDComm message in its plaintext form, not packaged into any protective envelope, is known as a **DIDComm plaintext message**.

When higher-level protocols are built atop DIDComm Messaging, applications remove protective envelopes and process the plaintext that’s inside. They think about protective envelopes the way webapps think about TLS: as required background context, not as a focus. Thus, application-level constructs are embodied in features of plaintext messages, and specifications for higher-level protocols typically document message structure and provide examples in this format.

In isolation, plaintext messages lack confidentiality and integrity guarantees, and are repudiable. They are therefore not normally transported across security boundaries. However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics, and it is the format used in this specification to give examples of headers and other internals. Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm Messaging data at rest.

The media type for a generic DIDComm plaintext message MUST be reported as `application/didcomm-plain+json` by conformant implementations.

The media type of the envelope MAY be set in the [`typ` property](https://tools.ietf.org/html/rfc7515#section-4.1.9) of the plaintext; it SHOULD be set if the message is intended for use without a signature or encryption.

### DIDComm Signed Messages

A **DIDComm signed message** is a signed [JWM](https://tools.ietf.org/html/draft-looker-jwm-01) envelope that associates a non-repudiable signature with the plaintext message inside it.

Signed messages are not necessary to provide message integrity (tamper evidence), or to prove the sender to the recipient. Both of these guarantees automatically occur with the authenticated encryption in DIDComm encrypted messages. Signed messages are only necessary when the origin of plaintext has to be provable to third parties, or when the sender can’t be proven to the recipient by authenticated encryption because the recipient is not known in advance (e.g., in a broadcast scenario). Adding a signature when one is not needed can degrade rather than enhance security because it [relinquishes the sender’s ability to speak off the record](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0049-repudiation/README.md#summary). We therefore expect signed messages to be used in a few cases, but not as a matter of course.

When a message is *both* signed and encrypted, this spec echoes the [JOSE recommendation about how to combine](https://datatracker.ietf.org/doc/html/rfc7519#section-11.2): sign the plaintext first, and then encrypt. (The opposite order would imply that the signer committed to opaque data. This would be less safe, and would undermine non-repudiation.)

The [media type](https://tools.ietf.org/html/rfc6838) of a DIDComm signed message MUST be `application/didcomm-signed+json`.

The media type of the envelope SHOULD be set in the [`typ` property](https://tools.ietf.org/html/rfc7515#section-4.1.9) of the JWS.

In order to avoid [surreptitious forwarding or malicious usage](https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html) of a signed message, a signed message SHOULD contain a properly defined `to` header. In the case where a message is *both* signed and encrypted, the inner (signed) JWM being signed MUST contain a `to` header.

### DIDComm Encrypted Messages

A **DIDComm encrypted message** is an encrypted [JWM](https://tools.ietf.org/html/draft-looker-jwm-01). It hides its content from all but authorized recipients, discloses and proves the sender to exactly and only those recipients, and provides integrity guarantees. It is important in privacy-preserving routing. It is what normally moves over network transports in DIDComm Messaging applications, and is the safest format for storing DIDComm Messaging data at rest.

The [media type](https://tools.ietf.org/html/rfc6838) of a non-nested DIDComm encrypted message MUST be `application/didcomm-encrypted+json`.

The media type of the envelope SHOULD be set in the [`typ` property](https://tools.ietf.org/html/rfc7516#section-4.1.11) of the JWE.



## Standards and Protocols

- **Decentralized Identity Foundation (DIF)**:
- [DIDComm Messaging Specification v2 Editor's Draft (identity.foundation)](https://identity.foundation/didcomm-messaging/spec/)



## API

### Attachment:

```c
// New a AttachmentData via base64 / JSON.
// Params [base64] : Base64 data used to construct AttachmentData.
// Params [json] : JSON data used to construct AttachmentData.
// Params [json_type] : JSON Type.
// Return [char *] : a AttachmentData if successful, or NULL if failed.

AttachmentData *attachmentdata_new_base64(char *base64);
AttachmentData *attachmentdata_new_json(unsigned int json_type, void *json);
```



```c
// Get the Attachment handle from AttachmentData
// Params [AttachmentData *] : AttachmentData for DIDComm. See the structure list for details.
// Return [char *] : a Attachment handle if successful, or NULL if failed.

Attachment *attachment_new(AttachmentData *data);
```



```c
// A set of "attachment_set_xxx" APIs to set property data for Attachment.
// Params [Attachment *] : Attachment handle from "attachment_new()".
// Params [xxx] : a property data to be set.
// Return [char *] : a Attachment handle if successful, or NULL if failed.

Attachment *attachment_set_id(Attachment *attachment, char *id);
Attachment *attachment_set_description(Attachment *attachment, char *description);
Attachment *attachment_set_filename(Attachment *attachment, char *filename);
Attachment *attachment_set_media_type(Attachment *attachment, char *media_type);
Attachment *attachment_set_format(Attachment *attachment, char *format);
Attachment *attachment_set_lastmod_time(Attachment *attachment, time_t lastmod_time);
Attachment *attachment_set_byte_count(Attachment *attachment, unsigned int byte_count);
```



### Message:

```c
// New a Message struct.
// Params [id] : Message ID. The id attribute value MUST be unique to the sender, across all messages they send. 
// Params [type_] :  A URI that associates the body of a message with a published and versioned schema.
// Params [body_type] :  a type of the body.
// Params [body] :   The body attribute contains all the data and structure that are uniquely defined for the schema associated with the type attribute. It maybe NULL.
// Return [Message *] : a point to the Message struct if successful, or NULL if failed.

Message *message_new(char *id, char *type_, unsigned int body_type, void *body);
```



```c
// A set of "message_set_xxx" APIs to set property data for Message.
// Params [Message *] : Message handle from "attachment_new()".
// Params [xxx] : a property data to be set.
// Return [Message *] : a point to the Message struct if successful, or NULL if failed.

Message *message_set_to(Message *message, char *to);
Message *message_set_from(Message *message, char *from);
Message *message_set_thid(Message *message, char *thid);
Message *message_set_pthid(Message *message, char *pthid);
Message *message_set_created_time(Message *message, time_t created_time);
Message *message_set_expires_time(Message *message, time_t expires_time);
Message *message_set_from_prior(Message *message, char *from_prior);
Message *message_set_attachment(Message *message, Attachment *attachment);
```



### DIDComm：

```c
// Generate a plaintext DIDComm from Message Structure.
// Params [Message *] : Message handle from "attachment_new()".
// Return [char *] : a plaintext DIDComm if successful, or NULL if failed.

char *didcomm_message_pack_plaintext(Message *message);
```



```c
// Generate a signed DIDComm from Message Structure.
// Params [Message *] : Message handle from "attachment_new()".
// Params [sign_by *] : The signer's did.
// Params [JWK *] : a JWK for signing.
// Return [char *] : a signed DIDComm if successful, or NULL if failed.

char *didcomm_message_pack_signed(Message *message, char *sign_by, JWK *jwk);
```



```c
// Generate a encrypted DIDComm from Message Structure.
// Params [Message *] : Message handle from "attachment_new()".
// Params [from *] : the DID of Sender.
// Params [to *] : a recipient's KaID.
// Params [sign_by *] : The signer's did.
// Params [PackEncryptedOptions *] : a option struct for Encrypt.See the structure list for details.
// Params [JWK *] : a JWK for Encrypt.
// Return [char *] : a signed DIDComm if successful, or NULL if failed.

char *didcomm_message_pack_encrypted(Message *message, char *from, char *to, char *sign_by, PackEncryptedOptions *option, JWK *jwk);
```



## Structure



```c
typedef struct _Base64AttachmentData {
  /// Base64-encoded data, when representing arbitrary content inline.
  char *base64;

  /// A JSON Web Signature over the content of the attachment.
  char *jws;  // skip_serializing_if = "Option::is_none"

} Base64AttachmentData;
```



```c
typedef struct _JsonAttachmentData {
  /// Directly embedded JSON data.
  unsigned int json_type;

  void *json;   
    
  /// A JSON Web Signature over the content of the attachment.
  char *jws; // skip_serializing_if = "Option::is_none"
} JsonAttachmentData;    
```



```c
typedef struct _LinksAttachmentData {
  /// A list of one or more locations at which the content may be fetched.
  char *links[4];

  /// The hash of the content encoded in multi-hash format. Used as an integrity check for the attachment.
  char *hash;

  /// A JSON Web Signature over the content of the attachment.
  char *jws; // skip_serializing_if = "Option::is_none"
} LinksAttachmentData;
```



```c
typedef struct _AttachmentData {
  AttachmentData_Type type;
  union {
    Base64AttachmentData base64_data;
    JsonAttachmentData json_data;
    LinksAttachmentData link_data;
	} data;
} AttachmentData;
```

  

```c
typedef struct _PackEncryptedOptions {

  /// If `true` and message is authenticated than information about sender will be protected from mediators, but
  /// additional re-encryption will be required. For anonymous messages this property will be ignored.
  bool protect_sender;

  /// Whether the encrypted messages need to be wrapped into `Forward` messages to be sent to Mediators
  /// as defined by the `Forward` protocol.
  bool forward;    // default = true

  /// if forward is enabled these optional headers can be passed to the wrapping `Forward` messages.
  /// If forward is disabled this property will be ignored.
  void *forward_headers;  // TODO: Option<HashMap<String, Value>>

  /// Identifier (DID URL) of messaging service (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
  /// If DID doc contains multiple messaging services it allows specify what service to use.
  /// If not present first service will be used.
  char *messaging_service;

  /// Algorithm used for authenticated encryption
  enum AuthCryptAlg enc_alg_auth;
    
  /// Algorithm used for anonymous encryption
  enum AnonCryptAlg enc_alg_anon;

} PackEncryptedOptions;
```



## Definition

### enum AuthCryptAlg

```c
enum AuthCryptAlg {
    /// AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-1PU key agreement with A256KW key wrapping
    A256cbcHs512Ecdh1puA256kw,
};
```



### enum AnonCryptAlg

```c
enum AnonCryptAlg {
    /// AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    A256cbcHs512EcdhEsA256kw,

    /// XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    Xc20pEcdhEsA256kw,

    /// A256GCM_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    A256gcmEcdhEsA256kw,
};
```



## Example

```c
cJSON *body_json = cJSON_CreateObject();
cJSON_AddStringToObject(body_json, "messagespecificattribute", "and its value");

Message *message = message_new("1234567890",
                               "http://example.com/protocols/lets_do_lunch/1.0/proposal",
                               0,
                               (void *)body_json);   

message_set_from(message, did_io); 
message_set_to(message, PEER_DID);

message_set_created_time(message, 1516269022);
message_set_expires_time(message, 1516385931);    

char* plaintext_message = didcomm_message_pack_plaintext(message);
if (plaintext_message)
    printf("Message [PlainText] :\n%s\n", plaintext_message);


char* signed_msg  = didcomm_message_pack_signed(message, did_io, jwk);
if (signed_msg) {
    printf("Message [Singed] :\n\%s\n", signed_msg);
}

PackEncryptedOptions option;
option.protect_sender = false;
option.enc_alg_anon = A256cbcHs512EcdhEsA256kw;
option.enc_alg_auth = A256cbcHs512Ecdh1puA256kw;

char *encrypted_msg = didcomm_message_pack_encrypted(message, did_io, peerdid_kid, did_io, &option, jwk);
if (encrypted_msg)
    printf("Message [Encrypted] : \n%s\n", encrypted_msg);
```



## output

```
Message [PlainText] :
{
        "id":   "1234567890",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:io:0xd12c8a04bd201d1d93adbea79e03632b6aea03ec",
        "to":   ["did:io:0xf354b0dcaa06b87a5fc0a205929988886b37195a#Key-p256-2147483618"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "body": {
                "messagespecificattribute":     "and its value"
        }
}

Message [Singed] :
{
        "payload":      "ewoJImlkIjoJIjEyMzQ1Njc4OTAiLAoJInR5cGUiOgkiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsCgkiZnJvbSI6CSJkaWQ6aW86MHhkMTJjOGEwNGJkMjAxZDFkOTNhZGJlYTc5ZTAzNjMyYjZhZWEwM2VjIiwKCSJ0byI6CVsiZGlkOmlvOjB4ZjM1NGIwZGNhYTA2Yjg3YTVmYzBhMjA1OTI5OTg4ODg2YjM3MTk1YSNLZXktcDI1Ni0yMTQ3NDgzNjE4Il0sCgkiY3JlYXRlZF90aW1lIjoJMTUxNjI2OTAyMiwKCSJleHBpcmVzX3RpbWUiOgkxNTE2Mzg1OTMxLAoJImJvZHkiOgl7CgkJIm1lc3NhZ2VzcGVjaWZpY2F0dHJpYnV0ZSI6CSJhbmQgaXRzIHZhbHVlIgoJfQp9",
        "signatures":   [{
                        "protected":    "ewoJInR5cCI6CSJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwKCSJhbGciOgkiRXMyNTZLIgp9",
                        "signature":    "uKf2HiDE0tZHHOY9u3PYHxi8bP8fSbrp_hN0gUqZ2WltvyRcUOuKSOaMBBk1EINvuqhZVYqO09MIv1tWpAhhCg",
                        "header":       {
                                "kid":  "did:io:0xd12c8a04bd201d1d93adbea79e03632b6aea03ec"
                        }
                }]
}

Message [Encrypted] :
{
        "ciphertext":   "12BySgN6n1I-EaeQGQ3rOvmxQ5RSw0crtPaFwNrO1egPSOQ_KP-zuWMUHBkdxgojH4L8RevqJ4v7EpUsuPXr9EXZGIs2W9X0ktHBIQeszWdiVUUjPXjiMtDQL6IVYzW814-V2UFXOvz9CCfG_HL3xqhZXPm7ZU7XbIeqTGMLjirBgIC_-eaM7F4NkJ7W3N7Kyb5EUtWoKAB06EhC_fCLkZKAiZ4eYEXTrLemAdpjOe1HG5Ojpo-jrY8nyI4mUe9frrypRQp5wVf1021QNX8MK179aCqHtdu0Gcrmn4gmzyyI8JXbAG-pWxuPdIp2oWtBwpqQiQTQAJPkUkDbem98_fKp2ZbMX6rUL_r3v2Qim4yy575HsVm4l_sbjaNIBNsiid9HMipTQdADWLI-SIKC1zzb3Uw6XW3iN9R2rbBctW9SB5qcGc_oDxTIrhepWs2YA6lKCaZpprV7NWRJ4HEHifDy",
        "protected":    "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6aW86MHhkMTJjOGEwNGJkMjAxZDFkOTNhZGJlYTc5ZTAzNjMyYjZhZWEwM2VjIiwiYXB1IjoiWkdsa09tbHZPakI0WkRFeVl6aGhNRFJpWkRJd01XUXhaRGt6WVdSaVpXRTNPV1V3TXpZek1tSTJZV1ZoTURObFl3IiwiYXB2Ijoib1hIeFNfd0FKSUszOU9IYlgzeWk4Q3JjNkREcDRPZkkwb1FpZ3VnNWMtayIsImVwayI6eyJjcnYiOiJQLTI1NiIsIngiOiJkQVdobFNGQlNQOHF4ajdfSTdtb21fUG5VbWJSVjJLOFNJMmNrR3I1Y1hBIiwieSI6Ind0UmtaNXJUbENqVjd2a08ycmVmaHBlWWN5bVFGTUZUNVAwRUV4cFNfVmMiLCJrdHkiOiJFQyIsImtpZCI6IktleS1wMjU2LTIxNDc0ODM2MjEifX0",
        "recipients":   [{
                        "header":       {
                                "kid":  "did:io:0xf354b0dcaa06b87a5fc0a205929988886b37195a#Key-p256-2147483618"
                        },
                        "encrypted_key":        "yImDYC57W0MJpbqnQsjTMCVa8BCn48ejRW43SZSEIE8kv-s9X0VHki0ksjaMnfqL"
                }],
        "tag":  "IR-vYeAoEgU-G9ca52X4Xw",
        "iv":   "3rBg7mAbD99njLDIgA"
}
```











