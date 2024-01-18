#pragma once

#ifdef ESP8266
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#else
#error Platform not supported
#endif

#define IOTEX_SPROUT_HTTP_HOST              "sprout-staging.w3bstream.com"
#define IOTEX_SPROUT_HTTP_PORT              9000
#define IOTEX_SPROUT_HTTP_TIMEOUT           3000
#define IOTEX_SPROUT_HTTP_PATH_MESSAGE      "/message"
#define IOTEX_SPROUT_HTTP_PATH_CREDENTIAL   "/sign_credential"

HTTPClient httpClient;

int iotex_sprout_did_http_get_jwt(WiFiClient &client, const char *vc) 
{
    httpClient.begin(client, IOTEX_SPROUT_HTTP_HOST, IOTEX_SPROUT_HTTP_PORT, IOTEX_SPROUT_HTTP_PATH_CREDENTIAL);
    httpClient.addHeader("Content-Type", "application/json");

    int httpCode = httpClient.POST(vc);
    if (httpCode > 0) {
        Serial.printf("[HTTP] POST... code: %d\n", httpCode);
 
        if (httpCode == HTTP_CODE_OK) {
          const String& payload = httpClient.getString();
          Serial.println("received payload:\n<<");
          Serial.println(payload);
          Serial.println(">>");
        }
    } else {
      Serial.printf("[HTTP] POST... failed, error: %s\n", httpClient.errorToString(httpCode).c_str());
    }

    return 0;
}



