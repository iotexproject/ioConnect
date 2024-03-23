#ifndef __ENCRYPTED_H__
#define __ENCRYPTED_H__

#include <stdbool.h>

enum AuthCryptAlg {
    /// AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-1PU key agreement with A256KW key wrapping
    A256cbcHs512Ecdh1puA256kw,
};

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

typedef struct _MessagingServiceMetadata {
    /// Identifier (DID URL) of used messaging service.
    char *id;

    /// Service endpoint of used messaging service.
    char *service_endpoint;
} MessagingServiceMetadata;

typedef struct _PackEncryptedMetadata {
    /// Information about messaging service used for message preparation.
    /// Practically `service_endpoint` field can be used to transport the message.
    MessagingServiceMetadata *messaging_service;

    /// Identifier (DID URL) of sender key used for message encryption.
    char *from_kid;

    /// Identifier (DID URL) of sender key used for message sign.
    char *sign_by_kid;

    /// Identifiers (DID URLs) of recipient keys used for message encryption.
    unsigned int to_kid_num;
    char *to_kids[4];
} PackEncryptedMetadata;

typedef struct _PackEncryptedOptions {
    /// If `true` and message is authenticated than information about sender will be protected from mediators, but
    /// additional re-encryption will be required. For anonymous messages this property will be ignored.
    bool protect_sender;

    /// Whether the encrypted messages need to be wrapped into `Forward` messages to be sent to Mediators
    /// as defined by the `Forward` protocol.
    bool forward;       // default = true

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

#endif

