#ifndef __UPLOAD_DATA_TEST_H__
#define __UPLOAD_DATA_TEST_H__

#define BIT_UPLOAD_DATA_CO2         0x1
#define BIT_UPLOAD_DATA_TVOC        0x2
#define BIT_UPLOAD_DATA_TEMP        0x4
#define BIT_UPLOAD_DATA_HUMIDITY    0x8
#define BIT_UPLOAD_DATA_MASK            (BIT_UPLOAD_DATA_CO2 | BIT_UPLOAD_DATA_TVOC | BIT_UPLOAD_DATA_TEMP | BIT_UPLOAD_DATA_HUMIDITY)
#define BIT_UPLOAD_DATA_MASK_COMPACT    (BIT_UPLOAD_DATA_CO2 | BIT_UPLOAD_DATA_TVOC)
#define BIT_UPLOAD_DATA_READY            BIT_UPLOAD_DATA_MASK
#define BIT_UPLOAD_DATA_READY_COMPACT    BIT_UPLOAD_DATA_MASK_COMPACT

enum upload_data_type {
    UPLOAD_DATA_CO2,
    UPLOAD_DATA_TVOC,
    UPLOAD_DATA_TEMP,
    UPLOAD_DATA_HUMIDITY,
};

struct upload_data {
    int valid_bit;
    int co2;
    int tvoc;
    float temp;
    int humidity;
};

#ifdef __cplusplus
extern "C" {
#endif

void iotex_upload_data_set_value(int value, enum upload_data_type data_type);

#ifdef __cplusplus
}
#endif


#endif

