#ifndef __DID_COMM_MESSAGE__
#define __DID_COMM_MESSAGE__

#include <time.h>

#include "include/jose/jwk.h"
#include "include/dids/didcomm/encrypted.h"

#define PLAINTEXT_TYP "application/didcomm-plain+json"

typedef enum _AttachmentData_Type {
    AttachmentData_Base64,
    AttachmentData_Json,
    AttachmentData_Links,
} AttachmentData_Type;

typedef struct _Base64AttachmentData {
    /// Base64-encoded data, when representing arbitrary content inline.
    char *base64;

    /// A JSON Web Signature over the content of the attachment.
    char *jws;  // skip_serializing_if = "Option::is_none"
} Base64AttachmentData;

typedef struct _JsonAttachmentData {
    /// Directly embedded JSON data.
    unsigned int json_type;
    void *json;    

    /// A JSON Web Signature over the content of the attachment.
    char *jws; // skip_serializing_if = "Option::is_none"
} JsonAttachmentData;

typedef struct _LinksAttachmentData {
    /// A list of one or more locations at which the content may be fetched.
    char *links[4];

    /// The hash of the content encoded in multi-hash format. Used as an integrity check for the attachment.
    char *hash;

    /// A JSON Web Signature over the content of the attachment.
    char *jws; // skip_serializing_if = "Option::is_none"
} LinksAttachmentData;

typedef struct _AttachmentData {
    AttachmentData_Type type;
    union {
        Base64AttachmentData base64_data;
        JsonAttachmentData json_data;
        LinksAttachmentData link_data;
    } data;
    
} AttachmentData;

typedef struct _attachment {
    /// A JSON object that gives access to the actual content of the attachment.
    /// Can be based on base64, json or external links.
    AttachmentData data; 

    /// Identifies attached content within the scope of a given message.
    ///  Recommended on appended attachment descriptors. Possible but generally unused
    ///  on embedded attachment descriptors. Never required if no references to the attachment
    ///  exist; if omitted, then there is no way to refer to the attachment later in the thread,
    ///  in error messages, and so forth. Because id is used to compose URIs, it is recommended
    ///  that this name be brief and avoid spaces and other characters that require URI escaping.
    char *id;               // skip_serializing_if = "Option::is_none"

    /// A human-readable description of the content.
    char *description;      // skip_serializing_if = "Option::is_none"

    /// A hint about the name that might be used if this attachment is persisted as a file.
    /// It is not required, and need not be unique. If this field is present and mime-type is not,
    /// the extension on the filename may be used to infer a MIME type.
    char *filename;         // skip_serializing_if = "Option::is_none"

    /// Describes the MIME type of the attached content.
    char *media_type;       // skip_serializing_if = "Option::is_none"

    /// Describes the format of the attachment if the mime_type is not sufficient.
    char *format;           // skip_serializing_if = "Option::is_none"

    /// A hint about when the content in this attachment was last modified
    /// in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
    time_t lastmod_time;    // skip_serializing_if = "Option::is_none"
    /// Mostly relevant when content is included by reference instead of by value.
    /// Lets the receiver guess how expensive it will be, in time, bandwidth, and storage,
    /// to fully fetch the attachment.
    unsigned int byte_count;// skip_serializing_if = "Option::is_none"
} Attachment;

typedef struct _message {
    /// Message id. Must be unique to the sender.
    char *id;

    /// Optional, if present it must be "application/didcomm-plain+json"
    char *typ;      // default = "default_typ"

    /// Message type attribute value MUST be a valid Message Type URI,
    /// that when resolved gives human readable information about the message.
    /// The attribute’s value also informs the content of the message,
    /// or example the presence of other attributes and how they should be processed.
    char *type;      // rename = "type"

    unsigned int body_type;
    /// Message body.
    void *body;

    /// Sender identifier. The from attribute MUST be a string that is a valid DID
    /// or DID URL (without the fragment component) which identifies the sender of the message.
    char *from;         // skip_serializing_if = "Option::is_none"

    /// Identifier(s) for recipients. MUST be an array of strings where each element
    /// is a valid DID or DID URL (without the fragment component) that identifies a member
    /// of the message’s intended audience.
    char *to[4];        // skip_serializing_if = "Option::is_none"

    /// Uniquely identifies the thread that the message belongs to.
    /// If not included the id property of the message MUST be treated as the value of the `thid`.
    char *thid;         // skip_serializing_if = "Option::is_none"

    /// If the message is a child of a thread the `pthid`
    /// will uniquely identify which thread is the parent.
    char *pthid;        // skip_serializing_if = "Option::is_none"

    /// Custom message headers. HashMap<String, Value>   
    void *extra_headers;// TODO. skip_serializing_if = "HashMap::is_empty"

    /// The attribute is used for the sender
    /// to express when they created the message, expressed in
    /// UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
    /// This attribute is informative to the recipient, and may be relied on by protocols.
    time_t created_time;    // skip_serializing_if = "Option::is_none"

    /// The expires_time attribute is used for the sender to express when they consider
    /// the message to be expired, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
    /// This attribute signals when the message is considered no longer valid by the sender.
    /// When omitted, the message is considered to have no expiration by the sender.
    time_t expires_time;    // skip_serializing_if = "Option::is_none"

    /// from_prior is a compactly serialized signed JWT containing FromPrior value
    char *from_prior;        // skip_serializing_if = "Option::is_none"

    /// Message attachments
    Attachment *attachments[4];   // skip_serializing_if = "Option::is_none"

} Message;

Attachment *attachment_new(AttachmentData *data);
Attachment *attachment_set_id(Attachment *attachment, char *id);
Attachment *attachment_set_description(Attachment *attachment, char *description);
Attachment *attachment_set_filename(Attachment *attachment, char *filename);
Attachment *attachment_set_media_type(Attachment *attachment, char *media_type);
Attachment *attachment_set_format(Attachment *attachment, char *format);
Attachment *attachment_set_lastmod_time(Attachment *attachment, time_t lastmod_time);
Attachment *attachment_set_byte_count(Attachment *attachment, unsigned int byte_count);

AttachmentData *attachmentdata_new_base64(char *base64);
AttachmentData *attachmentdata_new_json(unsigned int json_type, void *json);

Message *message_new(char *id, char *type_, unsigned int body_type, void *body);
Message *message_set_to(Message *message, char *to);
Message *message_set_from(Message *message, char *from);
Message *message_set_thid(Message *message, char *thid);
Message *message_set_pthid(Message *message, char *pthid);
Message *message_set_created_time(Message *message, time_t created_time);
Message *message_set_expires_time(Message *message, time_t expires_time);
Message *message_set_from_prior(Message *message, char *from_prior);
Message *message_set_attachment(Message *message, Attachment *attachment);

char *didcomm_message_pack_plaintext(Message *message);
char *didcomm_message_pack_signed(Message *message, char *sign_by, JWK *jwk);
char *didcomm_message_pack_encrypted(Message *message, char *from, char *to, char *sign_by, PackEncryptedOptions *option, JWK *jwk);

#endif 

