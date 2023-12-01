#ifndef IOTEX_MD_WRAP_H
#define IOTEX_MD_WRAP_H

#include "include/iotex/build_info.h"

#include "include/iotex/md.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
struct iotex_md_info_t
{
    /** Name of the message digest */
    const char * name;

    /** Digest identifier */
    iotex_md_type_t type;

    /** Output length of the digest function in bytes */
    unsigned char size;

    /** Block length of the digest function in bytes */
    unsigned char block_size;
};

#if defined(IOTEX_MD5_C)
extern const iotex_md_info_t iotex_md5_info;
#endif
#if defined(IOTEX_RIPEMD160_C)
extern const iotex_md_info_t iotex_ripemd160_info;
#endif
#if defined(IOTEX_SHA1_C)
extern const iotex_md_info_t iotex_sha1_info;
#endif
#if defined(IOTEX_SHA224_C)
extern const iotex_md_info_t iotex_sha224_info;
#endif
#if defined(IOTEX_SHA256_C)
extern const iotex_md_info_t iotex_sha256_info;
#endif
#if defined(IOTEX_SHA384_C)
extern const iotex_md_info_t iotex_sha384_info;
#endif
#if defined(IOTEX_SHA512_C)
extern const iotex_md_info_t iotex_sha512_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* IOTEX_MD_WRAP_H */
