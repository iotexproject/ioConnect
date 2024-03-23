#ifndef __ENVELOPE_H__
#define __ENVELOPE_H__

#define DIDCOMM_SIGN_TYP "application/didcomm-signed+json"

enum Envelope_Algorithm {
    ENVELOPE_EdDSA,
    ENVELOPE_Es256,
    ENVELOPE_Es256K,
    ENVELOPE_Other,
};
/*
typedef struct _CompactHeader {
    /// Media type of this complete JWS.
    char *typ;

    /// Cryptographic algorithm used to produce signature.
    enum Envelope_Algorithm alg;

    /// KID used to produce signature as DID URL.
    char *kid;
} CompactHeader;

typedef struct _sigHeader {
    /// KID used to produce signature as DID URL.
    char *kid;
} sigHeader;

typedef struct _ProtectedHeader {
    /// Must be `application/didcomm-signed+json` or `didcomm-signed+json` for now.
    /// Something like `application/didcomm-signed+cbor` can be introduced in the
    /// future.
    char *typ;

    /// Cryptographic algorithm used to produce signature.
    enum Envelope_Algorithm alg;
} ProtectedHeader;

typedef struct _Signature {
    /// JWS unprotected header
    /// Note it isn't serialized and not integrity protected
    sigHeader *header;

    /// BASE64URL(UTF8(JWS Protected Header))
    char *_protected;

    /// BASE64URL(JWS signature)
    /// Note JWS signature input is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
    char *signature;
} Signature;

typedef struct _JWS {
    /// Array of signatures
    Signature *signatures[4];

    /// BASE64URL(JWS Payload)
    char *payload;
} JWS;
*/
#endif
