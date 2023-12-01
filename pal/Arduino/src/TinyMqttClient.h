#ifndef __TINYMQTTCLIENT_H__
#define __TINYMQTTCLIENT_H__

#include <Arduino.h>
#include "IPAddress.h"
#include "Client.h"

#define TINY_MQTT_MAX_PACKET_SIZE 384
#define TINY_MQTT_KEEPALIVE 15
#define TINY_MQTT_SOCKET_TIMEOUT 15

#define TINY_MQTT_CONNECTION_TIMEOUT        -4
#define TINY_MQTT_CONNECTION_LOST           -3
#define TINY_MQTT_CONNECT_FAILED            -2
#define TINY_MQTT_DISCONNECTED              -1
#define TINY_MQTT_CONNECTED                 0
#define TINY_MQTT_CONNECT_BAD_PROTOCOL      1
#define TINY_MQTT_CONNECT_BAD_CLIENT_ID     2
#define TINY_MQTT_CONNECT_UNAVAILABLE       3
#define TINY_MQTT_CONNECT_BAD_CREDENTIALS   4
#define TINY_MQTT_CONNECT_UNAUTHORIZED      5

#define TINY_MQTT_MAX_HEADER_SIZE           5

#if defined(ESP8266) || defined(ESP32)
#include <functional>
#define TINY_MQTT_CALLBACK_SIGNATURE std::function<void(char*, uint8_t*, unsigned int)> callback
#else
#define TINY_MQTT_CALLBACK_SIGNATURE void (*callback)(char*, uint8_t*, unsigned int)
#endif

#define TINY_MQTT_EVENT_CALLBACK_SIGNATURE void (*event_callback)(uint8_t, void*)

#define CHECK_STRING_LENGTH(l,s) if (l+2+strnlen(s, this->bufferSize) > this->bufferSize) {_client->stop();return false;}

struct commenResult
{
    uint8_t value;
};

struct subscribeResult
{
    uint8_t pID[2];
    uint8_t value;
};

struct unsubscribeResult
{
    uint8_t pID[2];
};

struct publishResult
{
    char *topic;
    uint8_t *payload;
    uint32_t len;
};

struct eventResult
{
    union result
    {
        struct commenResult common;
        struct subscribeResult subscribe;
        struct unsubscribeResult unsubscribe;
        struct unsubscribeResult publish;
        struct publishResult data;
    }ret;
};

typedef enum tiny_mqtt_event_id_t {
    MQTT_EVENT_ERROR,                
    MQTT_EVENT_CONNECTED, 
    MQTT_EVENT_DISCONNECTED,
    MQTT_EVENT_SUBSCRIBED,  
    MQTT_EVENT_UNSUBSCRIBED, 
    MQTT_EVENT_PUBLISHED,    
    MQTT_EVENT_DATA,         
} tiny_mqtt_event_id_t;

//class TinyMqttClient : public Client {
class TinyMqttClient {
private:
    Client* _client;

    uint8_t* buffer;
    uint16_t bufferSize;
    uint16_t keepAlive;
    uint16_t socketTimeout;
    uint16_t nextMsgId;
    unsigned long lastOutActivity;
    unsigned long lastInActivity;
    bool pingOutstanding;
    TINY_MQTT_CALLBACK_SIGNATURE;
    TINY_MQTT_EVENT_CALLBACK_SIGNATURE;
    uint32_t readPacket(uint8_t*);
    bool readByte(uint8_t * result);
    bool readByte(uint8_t * result, uint16_t * index);
    bool write(uint8_t header, uint8_t* buf, uint16_t length);
    uint16_t writeString(const char* string, uint8_t* buf, uint16_t pos);
    size_t buildHeader(uint8_t header, uint8_t* buf, uint16_t length);

    IPAddress ip;
    const char* domain;
    uint16_t port;
    int _state;

public:
    TinyMqttClient(Client *client);
    TinyMqttClient(Client& client);
    ~TinyMqttClient();

    void setServer(IPAddress ip, uint16_t port);
    void setServer(uint8_t * ip, uint16_t port);
    void setServer(const char * domain, uint16_t port);
    void setCallback(TINY_MQTT_CALLBACK_SIGNATURE);
    void setEventCallback(TINY_MQTT_EVENT_CALLBACK_SIGNATURE);
    void setClient(Client& client);
    void setKeepAlive(uint16_t keepAlive);
    void setSocketTimeout(uint16_t timeout);

    bool setBufferSize(uint16_t size);
    uint16_t getBufferSize();

    bool connect(const char* id);
    bool connect(const char* id, const char* user, const char* pass);
    bool connect(const char* id, const char* user, const char* pass, const char* willTopic, uint8_t willQos, bool willRetain, const char* willMessage, bool cleanSession);

    void disconnect();

    bool publish(const char* topic, const uint8_t * payload, unsigned int plength);
    bool publish(const char* topic, const uint8_t * payload, unsigned int plength, bool retained);

    bool subscribe(const char* topic);
    bool subscribe(const char* topic, uint8_t qos);
    bool unsubscribe(const char* topic);

    bool loop();
    uint8_t connected();
    int state();

    virtual size_t write(uint8_t);
    virtual size_t write(const uint8_t *buffer, size_t size);
    virtual int connect(IPAddress ip, uint16_t port);
    virtual int connect(const char *host, uint16_t port);
// #ifdef ESP8266
//     virtual int connect(const IPAddress& ip, uint16_t port) { return 0; }; /* ESP8266 core defines this pure virtual in Client.h */
// #endif
//     virtual int available() {return _client->available();;};
//     virtual int read() {return 0;};
//     virtual int read(uint8_t *buf, size_t size) {return 0;};
//     virtual int peek() {return _client->peek();};
//     virtual void flush() {return _client->flush();};
//     virtual void stop() {return _client->stop();};
//     virtual operator bool() {return true;};   
};


#endif
