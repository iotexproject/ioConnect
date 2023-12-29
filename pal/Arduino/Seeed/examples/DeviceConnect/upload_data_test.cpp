#include <Arduino.h>
#include <DeviceConnect_Core.h>
#include "upload_data_test.h"


struct upload_data g_upload_data = {0};

void iotex_upload_data_set_value(int value, enum upload_data_type data_type)
{
    switch (data_type) {
        case UPLOAD_DATA_CO2:

            g_upload_data.co2 = value;
            g_upload_data.valid_bit |= BIT_UPLOAD_DATA_CO2;

            break;
        case UPLOAD_DATA_TVOC:

            g_upload_data.tvoc = value;
            g_upload_data.valid_bit |= BIT_UPLOAD_DATA_TVOC;

            break;
#ifndef UPLOAD_DATA_TYPE_COMPACT            
        case UPLOAD_DATA_TEMP:

            g_upload_data.temp = (float)value / 10.0;
            g_upload_data.valid_bit |= BIT_UPLOAD_DATA_TEMP;

            break;
        case UPLOAD_DATA_HUMIDITY:

            g_upload_data.humidity = value;
            g_upload_data.valid_bit |= BIT_UPLOAD_DATA_HUMIDITY;

            break;
#endif            
        default:
            break;
    }

#ifdef UPLOAD_DATA_TYPE_COMPACT
    if ((BIT_UPLOAD_DATA_READY_COMPACT == g_upload_data.valid_bit & BIT_UPLOAD_DATA_MASK_COMPACT)) {
#else
    if ((BIT_UPLOAD_DATA_READY == g_upload_data.valid_bit & BIT_UPLOAD_DATA_MASK)) {
#endif 
    
        cJSON *user_data = cJSON_CreateObject();

        cJSON_AddNumberToObject(user_data, "co2", g_upload_data.co2);
        cJSON_AddNumberToObject(user_data, "tvoc", g_upload_data.tvoc);

#ifdef UPLOAD_DATA_TYPE_COMPACT    
        cJSON_AddNullToObject(user_data, "temp");
        cJSON_AddNullToObject(user_data, "humidity");
#else
        cJSON_AddNumberToObject(user_data, "temp", g_upload_data.temp);
        cJSON_AddNumberToObject(user_data, "humidity", g_upload_data.humidity);
#endif

extern uint8_t macAddress[6];        
        iotex_dev_access_data_upload_with_userdata(user_data, 1, IOTEX_USER_DATA_TYPE_JSON, (int8_t *)macAddress);

// #ifdef UPLOAD_DATA_TYPE_COMPACT    
//         printf("Upload : [co2] : %d, [tvoc] : %d\n", g_upload_data.co2, g_upload_data.tvoc);
// #else
//         printf("Upload : [co2] : %d, [tvoc] : %d, [temp] : %.1f, [humidity] : %d\n", g_upload_data.co2, g_upload_data.tvoc, g_upload_data.temp, g_upload_data.humidity);
// #endif

        cJSON_Delete(user_data);

        g_upload_data.valid_bit = 0;
    }
}