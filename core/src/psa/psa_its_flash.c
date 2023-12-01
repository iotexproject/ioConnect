#include "include/common.h"

#if defined(CONFIG_PSA_ITS_FLASH_C)

#if defined(IOTEX_PLATFORM_C)
#include "include/iotex/platform.h"
#else
#define iotex_snprintf   snprintf
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

#include "include/server/crypto/psa_crypto_its.h"
#include "include/hal/flash/flash_common.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

flash_drv *its_flash = NULL;

/* The maximum value of psa_storage_info_t.size */
#define PSA_ITS_MAX_SIZE 0xffffffff

#define PSA_ITS_MAGIC_STRING "PSA\0ITS\0"
#define PSA_ITS_MAGIC_LENGTH 8

typedef struct
{
    uint8_t magic[PSA_ITS_MAGIC_LENGTH];
    uint8_t size[sizeof( uint32_t )];
    uint8_t flags[sizeof( psa_storage_create_flags_t )];
} psa_its_flash_header_t;

static psa_status_t psa_its_read_flash( psa_storage_uid_t uid,
                                       struct psa_storage_info_t *p_info)
{
    psa_its_flash_header_t header;
    size_t n;

    n = its_flash->read(its_flash->start_address, (uid - 1) * IOTEX_HAL_FLASH_KEY_SLOT_SIZE, (unsigned char *)&header, sizeof( header ));
    if( n != sizeof( header ) )
        return( PSA_ERROR_DATA_CORRUPT );
    if( memcmp( header.magic, PSA_ITS_MAGIC_STRING,
                PSA_ITS_MAGIC_LENGTH ) != 0 )             
        return( PSA_ERROR_DOES_NOT_EXIST );

    p_info->size = ( header.size[0] |
                     header.size[1] << 8 |
                     header.size[2] << 16 |
                     header.size[3] << 24 );
    p_info->flags = ( header.flags[0] |
                      header.flags[1] << 8 |
                      header.flags[2] << 16 |
                      header.flags[3] << 24 );
    return( PSA_SUCCESS );
}

psa_status_t psa_its_get_info( psa_storage_uid_t uid,
                               struct psa_storage_info_t *p_info )
{
    return psa_its_read_flash( uid, p_info );
}

psa_status_t psa_its_get( psa_storage_uid_t uid,
                          uint32_t data_offset,
                          uint32_t data_length,
                          void *p_data,
                          size_t *p_data_length )
{
    psa_status_t status;
    size_t n;
    struct psa_storage_info_t info;

    status = psa_its_read_flash( uid, &info );
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

    n = its_flash->read(its_flash->start_address, (uid - 1) * IOTEX_HAL_FLASH_KEY_SLOT_SIZE + sizeof(psa_its_flash_header_t), p_data, data_length );
    if( n != data_length )
        goto exit;
    status = PSA_SUCCESS;
    if( p_data_length != NULL )
        *p_data_length = n;

exit:
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
    psa_its_flash_header_t header;
    size_t n;

    memcpy( header.magic, PSA_ITS_MAGIC_STRING, PSA_ITS_MAGIC_LENGTH );
    IOTEX_PUT_UINT32_LE( data_length, header.size, 0 );
    IOTEX_PUT_UINT32_LE( create_flags, header.flags, 0 );

    status = PSA_ERROR_INSUFFICIENT_STORAGE;
    n = its_flash->write(its_flash->start_address, (uid - 1) * IOTEX_HAL_FLASH_KEY_SLOT_SIZE, (unsigned char *)&header, sizeof( header ));
    if( n != sizeof( header ) )
        goto exit;
    if( data_length != 0 )
    {
        n = its_flash->write(its_flash->start_address, (uid - 1) * IOTEX_HAL_FLASH_KEY_SLOT_SIZE + sizeof( header ), (unsigned char *)p_data, data_length);
        if( n != data_length )
            goto exit;
    }
    status = PSA_SUCCESS;

exit:
    return( status );
}

psa_status_t psa_its_remove( psa_storage_uid_t uid )
{
    its_flash->earse(its_flash->start_address + (uid - 1) * IOTEX_HAL_FLASH_KEY_SLOT_SIZE);

    return( PSA_SUCCESS );
}

#endif /* IOTEX_PSA_ITS_FILE_C */
