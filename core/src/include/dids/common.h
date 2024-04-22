#ifndef __IOTEX_DIDS_COMMON_H__
#define __IOTEX_DIDS_COMMON_H__

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>

typedef int did_status_t;   

#define DID_SUCCESS                     ((did_status_t)0)

#define DID_ERROR_PROGRAMMER_ERROR      ((did_status_t)-1)
#define DID_ERROR_CONNECTION_REFUSED    ((did_status_t)-2)
#define DID_ERROR_CONNECTION_BUSY       ((did_status_t)-3)
#define DID_ERROR_GENERIC_ERROR         ((did_status_t)-4)
#define DID_ERROR_NOT_PERMITTED         ((did_status_t)-5)
#define DID_ERROR_NOT_SUPPORTED         ((did_status_t)-6)
#define DID_ERROR_INVALID_ARGUMENT      ((did_status_t)-7)
#define DID_ERROR_INVALID_HANDLE        ((did_status_t)-8)
#define DID_ERROR_BAD_STATE             ((did_status_t)-9)
#define DID_ERROR_BUFFER_TOO_SMALL      ((did_status_t)-10)
#define DID_ERROR_ALREADY_EXISTS        ((did_status_t)-11)
#define DID_ERROR_DOES_NOT_EXIST        ((did_status_t)-12)
#define DID_ERROR_INSUFFICIENT_MEMORY   ((did_status_t)-13)
#define DID_ERROR_INSUFFICIENT_STORAGE  ((did_status_t)-14)
#define DID_ERROR_INSUFFICIENT_DATA     ((did_status_t)-15)
#define DID_ERROR_SERVICE_FAILURE       ((did_status_t)-16)
#define DID_ERROR_COMMUNICATION_FAILURE ((did_status_t)-17)
#define DID_ERROR_STORAGE_FAILURE       ((did_status_t)-18)
#define DID_ERROR_HARDWARE_FAILURE      ((did_status_t)-19)
#define DID_ERROR_INVALID_SIGNATURE     ((did_status_t)-20)
#define DID_ERROR_DEPENDENCY_NEEDED     ((did_status_t)-21)
#define DID_ERROR_CURRENTLY_INSTALLING  ((did_status_t)-22)
#define DID_ERROR_INTERNAL_COMPUTE      ((did_status_t)-23)
#define DID_ERROR_BUFFER_FULL           ((did_status_t)-24)
#define DID_ERROR_DATA_FORMAT           ((did_status_t)-25)


#endif