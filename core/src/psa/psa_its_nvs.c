#include "include/common.h"

#if defined(CONFIG_PSA_ITS_NVS_C)

#if defined(IOTEX_PLATFORM_C)
#include "include/iotex/platform.h"
#else
#define iotex_snprintf   snprintf
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

#include "include/server/crypto/psa_crypto_its.h"
#include "include/hal/nvs/nvs_common.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

nvs_drv *its_nvs = NULL;

#if !defined(PSA_ITS_STORAGE_PREFIX)
#define PSA_ITS_STORAGE_PREFIX ""
#endif

#define PSA_ITS_STORAGE_FILENAME_PATTERN "%08x"
#define PSA_ITS_STORAGE_SUFFIX ".its"
#define PSA_ITS_STORAGE_FILENAME_LENGTH         \
    ( sizeof( PSA_ITS_STORAGE_PREFIX ) - 1 + /*prefix without terminating 0*/ \
      8 + /*UID (64-bit number in hex)*/                               \
      sizeof( PSA_ITS_STORAGE_SUFFIX ) - 1 + /*suffix without terminating 0*/ \
      1 /*terminating null byte*/ )

/* The maximum value of psa_storage_info_t.size */
#define PSA_ITS_MAX_SIZE 0xffffffff

#define PSA_ITS_MAGIC_STRING "PSA\0ITS\0"
#define PSA_ITS_MAGIC_LENGTH 8

/* As rename fails on Windows if the new filepath already exists,
 * use MoveFileExA with the MOVEFILE_REPLACE_EXISTING flag instead.
 * Returns 0 on success, nonzero on failure. */
#if defined(_WIN32)
#define rename_replace_existing( oldpath, newpath ) \
    ( ! MoveFileExA( oldpath, newpath, MOVEFILE_REPLACE_EXISTING ) )
#else
#define rename_replace_existing( oldpath, newpath ) rename( oldpath, newpath )
#endif

typedef struct
{
    uint8_t magic[PSA_ITS_MAGIC_LENGTH];
    uint8_t size[sizeof( uint32_t )];
    uint8_t flags[sizeof( psa_storage_create_flags_t )];
} psa_its_file_header_t;

static void psa_its_fill_filename( psa_storage_uid_t uid, char *filename )
{
    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    iotex_snprintf( filename, PSA_ITS_STORAGE_FILENAME_LENGTH,
                      "%s" PSA_ITS_STORAGE_FILENAME_PATTERN "%s",
                      PSA_ITS_STORAGE_PREFIX,
//                      (unsigned) ( uid >> 32 ),
                      (unsigned) ( uid & 0xffffffff ),
                      PSA_ITS_STORAGE_SUFFIX );
}

psa_status_t psa_its_get_info( psa_storage_uid_t uid,
                               struct psa_storage_info_t *p_info )
{
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    psa_status_t status;
    psa_its_file_header_t header;
    iotex_nvs_handle_t handle = 0;
    size_t length = sizeof(header);

    psa_its_fill_filename( uid, filename );
    status = its_nvs->open(filename, IOTEX_NVS_READWRITE, &handle);
    if( status != PSA_SUCCESS ) {
        status = PSA_ERROR_DOES_NOT_EXIST;
        goto exit;
    }

    status = its_nvs->get_blob(handle, "header", (void *)&header, &length);
    if( status != PSA_SUCCESS ) {
        status = PSA_ERROR_DOES_NOT_EXIST;
        goto exit;
    }

    if( memcmp( header.magic, PSA_ITS_MAGIC_STRING,
                PSA_ITS_MAGIC_LENGTH ) != 0 ) {
        status = PSA_ERROR_DOES_NOT_EXIST;
        goto exit;
    }             

    p_info->size = ( header.size[0] |
                     header.size[1] << 8 |
                     header.size[2] << 16 |
                     header.size[3] << 24 );
    p_info->flags = ( header.flags[0] |
                      header.flags[1] << 8 |
                      header.flags[2] << 16 |
                      header.flags[3] << 24 );        
exit:
    if( handle != 0 )
        its_nvs->close(handle);

    return( status );
}

psa_status_t psa_its_get( psa_storage_uid_t uid,
                          uint32_t data_offset,
                          uint32_t data_length,
                          void *p_data,
                          size_t *p_data_length )
{
    psa_status_t status;
    iotex_nvs_handle_t handle = 0;
    psa_its_file_header_t header;
    size_t length = sizeof(header);
    struct psa_storage_info_t info;
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];

    psa_its_fill_filename( uid, filename );
    its_nvs->open(filename, IOTEX_NVS_READWRITE, &handle);
    if( handle == 0 )
        return( PSA_ERROR_DOES_NOT_EXIST );

    status = its_nvs->get_blob(handle, "header", (void *)&header, &length);
    if( length != sizeof( header ) )
        return( PSA_ERROR_DATA_CORRUPT );

    info.size = ( header.size[0] |
                     header.size[1] << 8 |
                     header.size[2] << 16 |
                     header.size[3] << 24 );
    info.flags = ( header.flags[0] |
                      header.flags[1] << 8 |
                      header.flags[2] << 16 |
                      header.flags[3] << 24 );        

    if( status != PSA_SUCCESS )
        goto exit;
    status = PSA_ERROR_INVALID_ARGUMENT;
    if( data_offset + data_length < data_offset )
        goto exit;
#if SIZE_MAX < 0xffffffff
    if( data_offset + data_length > SIZE_MAX )
        goto exit;
#endif
    if( data_offset + data_length > info.size )
        goto exit;

    status = PSA_ERROR_STORAGE_FAILURE;
#if LONG_MAX < 0xffffffff
    while( data_offset > LONG_MAX )
    {
        data_offset -= LONG_MAX;
    }
#endif
    length = data_length;
    status = its_nvs->get_blob(handle, "data", (void *)p_data, &length);
    if( length != data_length )
        goto exit;
    status = PSA_SUCCESS;
    if( p_data_length != NULL )
        *p_data_length = length;

exit:
    if( handle != 0 )
        its_nvs->close(handle);
    return( status );
}

psa_status_t psa_its_set( psa_storage_uid_t uid,
                          uint32_t data_length,
                          const void *p_data,
                          psa_storage_create_flags_t create_flags )
{
    if( uid == 0 )
    {
        return( PSA_ERROR_INVALID_HANDLE );
    }

    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    iotex_nvs_handle_t handle = 0;
    psa_its_file_header_t header;
    size_t n;

    memcpy( header.magic, PSA_ITS_MAGIC_STRING, PSA_ITS_MAGIC_LENGTH );
    IOTEX_PUT_UINT32_LE( data_length, header.size, 0 );
    IOTEX_PUT_UINT32_LE( create_flags, header.flags, 0 );

    psa_its_fill_filename( uid, filename );
    its_nvs->open(filename, IOTEX_NVS_READWRITE, &handle);
    if( handle == 0 )
        goto exit;

    status = PSA_ERROR_INSUFFICIENT_STORAGE;
    n = its_nvs->set_blob(handle, "header", &header, sizeof( header ));
    if( n != sizeof( header ) )
        goto exit;
    its_nvs->commit(handle);

    if( data_length != 0 )
    {
        n = its_nvs->set_blob(handle, "data", p_data, data_length);
        if( n != data_length )
            goto exit;
    }

    its_nvs->commit(handle);

    status = PSA_SUCCESS;
    
exit:
    if( handle != 0 )
    {
        its_nvs->close(handle);
    }

    return( status );
}

psa_status_t psa_its_remove( psa_storage_uid_t uid )
{
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    iotex_nvs_handle_t handle = 0;
    psa_its_fill_filename( uid, filename );

    its_nvs->open(filename, IOTEX_NVS_READWRITE, &handle);
    if( handle == 0 )
        return( PSA_ERROR_DOES_NOT_EXIST );

    if( its_nvs->erase_all( handle ) != 0 )
        return( PSA_ERROR_STORAGE_FAILURE );
    
    its_nvs->close(handle);
    return( PSA_SUCCESS );
}

#endif /* IOTEX_PSA_ITS_FILE_C */
