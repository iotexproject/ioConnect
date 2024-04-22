#ifndef __IOTEX_JOSE_COMMON_H__
#define __IOTEX_JOSE_COMMON_H__

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>

typedef int jose_status_t;   

#define JOSE_SUCCESS                     ((jose_status_t)0)

#define JOSE_ERROR_PROGRAMMER_ERROR      ((jose_status_t)-1)
#define JOSE_ERROR_CONNECTION_REFUSED    ((jose_status_t)-2)
#define JOSE_ERROR_CONNECTION_BUSY       ((jose_status_t)-3)
#define JOSE_ERROR_GENERIC_ERROR         ((jose_status_t)-4)
#define JOSE_ERROR_NOT_PERMITTED         ((jose_status_t)-5)
#define JOSE_ERROR_NOT_SUPPORTED         ((jose_status_t)-6)
#define JOSE_ERROR_INVALID_ARGUMENT      ((jose_status_t)-7)
#define JOSE_ERROR_INVALID_HANDLE        ((jose_status_t)-8)
#define JOSE_ERROR_BAD_STATE             ((jose_status_t)-9)
#define JOSE_ERROR_BUFFER_TOO_SMALL      ((jose_status_t)-10)
#define JOSE_ERROR_ALREADY_EXISTS        ((jose_status_t)-11)
#define JOSE_ERROR_DOES_NOT_EXIST        ((jose_status_t)-12)
#define JOSE_ERROR_INSUFFICIENT_MEMORY   ((jose_status_t)-13)
#define JOSE_ERROR_INSUFFICIENT_STORAGE  ((jose_status_t)-14)
#define JOSE_ERROR_INSUFFICIENT_DATA     ((jose_status_t)-15)
#define JOSE_ERROR_SERVICE_FAILURE       ((jose_status_t)-16)
#define JOSE_ERROR_COMMUNICATION_FAILURE ((jose_status_t)-17)
#define JOSE_ERROR_STORAGE_FAILURE       ((jose_status_t)-18)
#define JOSE_ERROR_HARDWARE_FAILURE      ((jose_status_t)-19)
#define JOSE_ERROR_INVALID_SIGNATURE     ((jose_status_t)-20)
#define JOSE_ERROR_DEPENDENCY_NEEDED     ((jose_status_t)-21)
#define JOSE_ERROR_CURRENTLY_INSTALLING  ((jose_status_t)-22)
#define JOSE_ERROR_INTERNAL_COMPUTE      ((jose_status_t)-23)
#define JOSE_ERROR_ENCRYPT_FAIL          ((jose_status_t)-24)
#define JOSE_ERROR_DECRYPT_FAIL          ((jose_status_t)-25)

#define JOSE_HEADER_TYPE_ENCRPT_TYPE        "application/didcomm-encrypted+json"        // DICOM_Standard_Committee
#define JOSE_HEADER_TYPE_SIGN_TYPE          "application/didcomm-signed+json"           // DICOM_Standard_Committee
#define JOSE_HEADER_TYPE_COMPACT            "JOSE"                                      // RFC 7515 (JWS)
#define JOSE_HEADER_TYPE_JSON               "JOSE+JSON"                                 // RFC 7515 (JWS)
#define JOSE_HEADER_TYPE_JWT                "JWT"                                       // RFC 7519 (JWT)

#define JOSE_JWE_RECIPIENTS_MAX         4

enum JWS_USAGE {
    JWS_USAGE_DIDCOMM,
    JWS_USAGE_JWT,
    JWS_USAGE_JSON,
    JWS_USAGE_COMPACT,
};


#endif