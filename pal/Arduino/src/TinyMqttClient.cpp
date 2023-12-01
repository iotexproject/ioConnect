#include <Arduino.h>
#include "TinyMqttClient.h"

#define TINY_MQTT_MESSAGE_TYPE_CONNECT      1
#define TINY_MQTT_MESSAGE_TYPE_CONNACK      2
#define TINY_MQTT_MESSAGE_TYPE_PUBLISH      3
#define TINY_MQTT_MESSAGE_TYPE_PUBACK       4
#define TINY_MQTT_MESSAGE_TYPE_PUBREC       5
#define TINY_MQTT_MESSAGE_TYPE_PUBREL       6
#define TINY_MQTT_MESSAGE_TYPE_PUBCOMP      7
#define TINY_MQTT_MESSAGE_TYPE_SUBSCRIBE    8
#define TINY_MQTT_MESSAGE_TYPE_SUBACK       9
#define TINY_MQTT_MESSAGE_TYPE_UNSUBSCRIBE 10
#define TINY_MQTT_MESSAGE_TYPE_UNSUBACK    11
#define TINY_MQTT_MESSAGE_TYPE_PINGREQ     12
#define TINY_MQTT_MESSAGE_TYPE_PINGRESP    13
#define TINY_MQTT_MESSAGE_TYPE_DISCONNECT  14

#define TINY_MQTT_QOS_0        (0 << 1)
#define TINY_MQTT_QOS_1        (1 << 1)
#define TINY_MQTT_QOS_2        (2 << 1)

TinyMqttClient::TinyMqttClient(Client *client) {
    this->_client = client;
    this->_state = TINY_MQTT_DISCONNECTED;
    this->bufferSize = 0;
    setBufferSize(TINY_MQTT_MAX_PACKET_SIZE);
    setKeepAlive(TINY_MQTT_KEEPALIVE);
    setSocketTimeout(TINY_MQTT_SOCKET_TIMEOUT);
}

TinyMqttClient::TinyMqttClient(Client& client) : TinyMqttClient(&client) {

}

TinyMqttClient::~TinyMqttClient() {
    if (this->buffer)
        free(this->buffer);
}

bool TinyMqttClient::connect(const char *id) {
    return connect(id,NULL,NULL,0,0,0,0,1);
}

int TinyMqttClient::connect(IPAddress ip, uint16_t port) {
    char tempId[14] = {0};
    snprintf(tempId, sizeof(tempId), "IoTex-%.8lx", millis());

    this->setServer(ip, port);
  
    return (int)this->connect(tempId, NULL, NULL);
}

int TinyMqttClient::connect(const char *host, uint16_t port) {
    char tempId[14] = {0};
    snprintf(tempId, sizeof(tempId), "IoTex-%.8lx", millis());

    this->setServer(host, port);
  
    return (int)this->connect(tempId, NULL, NULL);    
}

bool TinyMqttClient::connect(const char *id, const char *user, const char *pass) {
    return connect(id,user,pass,0,0,0,0,1);
}

bool TinyMqttClient::connect(const char *id, const char *user, const char *pass, const char* willTopic, uint8_t willQos, bool willRetain, const char* willMessage, bool cleanSession) {
    if (!connected()) {
        int result = 0;

        if(_client->connected()) {
            result = 1;
        } else {
            if (domain != NULL) {
                result = _client->connect(this->domain, this->port);
            } else {
                result = _client->connect(this->ip, this->port);
            }
        }

        if (result == 1) {
            nextMsgId = 1;
            uint16_t length = TINY_MQTT_MAX_HEADER_SIZE;
            unsigned int j;

            uint8_t d[7] = {0x00,0x04,'M','Q','T','T', 0x4};

#define MQTT_HEADER_VERSION_LENGTH 7

            for (j = 0;j<MQTT_HEADER_VERSION_LENGTH;j++) {
                this->buffer[length++] = d[j];
            }

            uint8_t v;
            if (willTopic) {
                v = 0x04|(willQos<<3)|(willRetain<<5);
            } else {
                v = 0x00;
            }
            if (cleanSession) {
                v = v|0x02;
            }

            if(user != NULL) {
                v = v|0x80;

                if(pass != NULL) {
                    v = v|(0x80>>1);
                }
            }
            this->buffer[length++] = v;

            this->buffer[length++] = ((this->keepAlive) >> 8);
            this->buffer[length++] = ((this->keepAlive) & 0xFF);

            CHECK_STRING_LENGTH(length,id)
            length = writeString(id,this->buffer,length);
            if (willTopic) {
                CHECK_STRING_LENGTH(length,willTopic)
                length = writeString(willTopic,this->buffer,length);
                CHECK_STRING_LENGTH(length,willMessage)
                length = writeString(willMessage,this->buffer,length);
            }

            if(user != NULL) {
                CHECK_STRING_LENGTH(length,user)
                length = writeString(user,this->buffer,length);
                if(pass != NULL) {
                    CHECK_STRING_LENGTH(length,pass)
                    length = writeString(pass,this->buffer,length);
                }
            }

            write(TINY_MQTT_MESSAGE_TYPE_CONNECT << 4, this->buffer, length - TINY_MQTT_MAX_HEADER_SIZE);

            lastInActivity = lastOutActivity = millis();

            while (!_client->available()) {
                unsigned long t = millis();
                if (t-lastInActivity >= ((int32_t) this->socketTimeout * 1000UL)) {
                    _state = TINY_MQTT_CONNECTION_TIMEOUT;
                    _client->stop();
                    printf("connect 2\n");
                    return false;
                }
            }
            uint8_t llen;
            uint32_t len = readPacket(&llen);

            if (len == 4) {
                if (buffer[3] == 0) {
                    lastInActivity = millis();
                    pingOutstanding = false;
                    _state = TINY_MQTT_CONNECTED;
                    return true;
                } else {
                    _state = buffer[3];
                }
            }
            _client->stop();
        } else {
            _state = TINY_MQTT_CONNECT_FAILED;
        }
        return false;
    }

    return true;
}

// reads a byte into result
bool TinyMqttClient::readByte(uint8_t * result) {
   uint32_t previousMillis = millis();
   while(!_client->available()) {
     yield();
     uint32_t currentMillis = millis();
     if(currentMillis - previousMillis >= ((int32_t) this->socketTimeout * 1000)){
       return false;
     }
   }
   *result = _client->read();
   return true;
}

// reads a byte into result[*index] and increments index
bool TinyMqttClient::readByte(uint8_t * result, uint16_t * index){
  uint16_t current_index = *index;
  uint8_t * write_address = &(result[current_index]);
  if(readByte(write_address)){
    *index = current_index + 1;
    return true;
  }
  return false;
}

uint32_t TinyMqttClient::readPacket(uint8_t* lengthLength) {
    uint16_t len = 0;
    if(!readByte(this->buffer, &len)) return 0;
    bool isPublish = (this->buffer[0]&0xF0) == (TINY_MQTT_MESSAGE_TYPE_PUBLISH << 4);
    uint32_t multiplier = 1;
    uint32_t length = 0;
    uint8_t digit = 0;
    uint16_t skip = 0;
    uint32_t start = 0;

    do {
        if (len == 5) {
            // Invalid remaining length encoding - kill the connection
            _state = TINY_MQTT_DISCONNECTED;
            _client->stop();
            return 0;
        }
        if(!readByte(&digit)) return 0;
        this->buffer[len++] = digit;
        length += (digit & 127) * multiplier;
        multiplier <<=7; //multiplier *= 128
    } while ((digit & 128) != 0);
    *lengthLength = len-1;

    if (isPublish) {
        // Read in topic length to calculate bytes to skip over for Stream writing
        if(!readByte(this->buffer, &len)) return 0;
        if(!readByte(this->buffer, &len)) return 0;
        skip = (this->buffer[*lengthLength+1]<<8)+this->buffer[*lengthLength+2];
        start = 2;
        if (this->buffer[0] & TINY_MQTT_QOS_1) {
            // skip message id
            skip += 2;
        }
    }
    uint32_t idx = len;

    for (uint32_t i = start;i<length;i++) {
        if(!readByte(&digit)) 
            return 0;
        if (len < this->bufferSize) {
            this->buffer[len] = digit;
            len++;
        }
        idx++;
    }

    if (idx > this->bufferSize) {
        len = 0; // This will cause the packet to be ignored.
    }
    return len;
}

bool TinyMqttClient::loop() {
    if (connected()) {
        unsigned long t = millis();
        if ((t - lastInActivity > this->keepAlive*1000UL) || (t - lastOutActivity > this->keepAlive*1000UL)) {
            if (pingOutstanding) {
                this->_state = TINY_MQTT_CONNECTION_TIMEOUT;
                _client->stop();
                return false;
            } else {
                this->buffer[0] = TINY_MQTT_MESSAGE_TYPE_PINGREQ << 4;
                this->buffer[1] = 0;
                _client->write(this->buffer, 2);
                lastOutActivity = t;
                lastInActivity = t;
                pingOutstanding = true;
            }
        }
        if (_client->available()) {
            uint8_t llen;
            uint16_t len = readPacket(&llen);
            uint16_t msgId = 0;
            uint8_t *payload;
            if (len > 0) {
                lastInActivity = t;
                uint8_t type = (this->buffer[0] >> 4) & 0x0F;
                
                switch (type) {
                case TINY_MQTT_MESSAGE_TYPE_CONNACK:
                    if (event_callback) {
                        int result = this->buffer[3];
                        struct eventResult eventRet;
                        eventRet.ret.common.value = this->buffer[2];
                        event_callback(MQTT_EVENT_CONNECTED, &eventRet);
                    }
                    break;
                case TINY_MQTT_MESSAGE_TYPE_DISCONNECT:
                    if (event_callback)
                        event_callback(MQTT_EVENT_DISCONNECTED, 0);
                    break;
                case TINY_MQTT_MESSAGE_TYPE_SUBACK:
                    if (event_callback) {
                        struct eventResult eventRet;
                        eventRet.ret.subscribe.pID[0] = this->buffer[2];
                        eventRet.ret.subscribe.pID[1] = this->buffer[3];
                        eventRet.ret.subscribe.value = this->buffer[4];
                        event_callback(MQTT_EVENT_SUBSCRIBED, &eventRet);
                    }
                    break;
                case TINY_MQTT_MESSAGE_TYPE_UNSUBACK:
                    if (event_callback) {
                        struct eventResult eventRet;
                        eventRet.ret.unsubscribe.pID[0] = this->buffer[2];
                        eventRet.ret.unsubscribe.pID[1] = this->buffer[3];
                        event_callback(MQTT_EVENT_UNSUBSCRIBED, &eventRet);
                    }
                    break;   
                case TINY_MQTT_MESSAGE_TYPE_PUBACK:
                    if (event_callback) {
                        struct eventResult eventRet;
                        eventRet.ret.publish.pID[0] = this->buffer[2];
                        eventRet.ret.publish.pID[1] = this->buffer[3];
                        event_callback(MQTT_EVENT_PUBLISHED, &eventRet);
                    }
                    break;   
                case TINY_MQTT_MESSAGE_TYPE_PUBLISH:
                    if (event_callback) {
                        uint16_t tl = (this->buffer[llen+1] << 8) + this->buffer[llen + 2];     /* topic length in bytes */
                        memmove(this->buffer + llen + 2, this->buffer + llen + 3, tl);          /* move topic inside buffer 1 byte to front */
                        this->buffer[llen + 2 + tl] = 0;                                        /* end the topic as a 'C' string with \x00 */
                        char *topic = (char*) this->buffer + llen + 2;
                        // msgId only present for QOS>0
                        if ((this->buffer[0] & 0x06) == TINY_MQTT_QOS_1) {
                            msgId = (this->buffer[llen + 3 + tl] << 8) + this->buffer[llen + 3 + tl + 1];
                            
                            struct eventResult eventRet;
                            eventRet.ret.data.topic = topic;
                            eventRet.ret.data.payload = this->buffer + llen + 3 + tl + 2;
                            eventRet.ret.data.len = len - llen - 3 - tl - 2;
                            event_callback(MQTT_EVENT_DATA, &eventRet);

                            this->buffer[0] = TINY_MQTT_MESSAGE_TYPE_PUBACK << 4;
                            this->buffer[1] = 2;
                            this->buffer[2] = (msgId >> 8);
                            this->buffer[3] = (msgId & 0xFF);
                            _client->write(this->buffer,4);
                            lastOutActivity = t;

                        } else {
                            struct eventResult eventRet;
                            eventRet.ret.data.topic = topic;
                            eventRet.ret.data.payload = this-> buffer + llen + 3 + tl;;
                            eventRet.ret.data.len = len - llen - 3 - tl;
                            event_callback(MQTT_EVENT_DATA, &eventRet);
                        }                        
                    }
                    break;    
                case TINY_MQTT_MESSAGE_TYPE_PINGREQ:   
                    this->buffer[0] = TINY_MQTT_MESSAGE_TYPE_PINGRESP << 4;
                    this->buffer[1] = 0;
                    _client->write(this->buffer,2);                                                                  
                    break;
                case TINY_MQTT_MESSAGE_TYPE_PINGRESP:   
                    pingOutstanding = false;                                                               
                    break;                    
                default:
                    break;
                }                
            } else if (!connected()) {
                // readPacket has closed the connection
                return false;
            }
        }
        return true;
    }
    return false;
}

bool TinyMqttClient::publish(const char* topic, const uint8_t* payload, unsigned int plength) {
    return publish(topic, payload, plength, false);
}

bool TinyMqttClient::publish(const char* topic, const uint8_t* payload, unsigned int plength, bool retained) {
    if (connected()) {
        if (this->bufferSize < TINY_MQTT_MAX_HEADER_SIZE + 2 + strnlen(topic, this->bufferSize) + plength) {
            return false;
        }
        
        uint16_t length = TINY_MQTT_MAX_HEADER_SIZE;
        length = writeString(topic, this->buffer, length);

        // Add payload
        uint16_t i;
        for (i = 0; i < plength; i++) {
            this->buffer[length++] = payload[i];
        }

        // Write the header
        uint8_t header = TINY_MQTT_MESSAGE_TYPE_PUBLISH << 4;
        if (retained) {
            header |= 1;
        }

        // header |= TINY_MQTT_QOS_1;
        return write(header, this->buffer, length - TINY_MQTT_MAX_HEADER_SIZE);
    }
    return false;
}

size_t TinyMqttClient::write(uint8_t data) {
    lastOutActivity = millis();
    return _client->write(data);
}

size_t TinyMqttClient::write(const uint8_t *buffer, size_t size) {
    lastOutActivity = millis();
    return _client->write(buffer,size);
}

size_t TinyMqttClient::buildHeader(uint8_t header, uint8_t* buf, uint16_t length) {
    uint8_t lenBuf[4];
    uint8_t llen = 0, pos = 0, encodeByte;
        
    do {
        encodeByte = length & 127; 
        length >>= 7;            
        if (length > 0) {
            encodeByte |= 0x80;
        }
        lenBuf[pos++] = encodeByte;
        llen++;
    } while(length > 0);

    buf[4-llen] = header;
    for (int i = 0; i < llen; i++) {
        buf[TINY_MQTT_MAX_HEADER_SIZE - llen + i] = lenBuf[i];
    }
    return llen + 1; // Full header size is variable length bit plus the 1-byte fixed header
}

bool TinyMqttClient::write(uint8_t header, uint8_t* buf, uint16_t length) {
    uint16_t rc;
    uint8_t hlen = buildHeader(header, buf, length);

    rc = _client->write(buf + (TINY_MQTT_MAX_HEADER_SIZE - hlen), length + hlen);
    lastOutActivity = millis();
    return (rc == hlen + length);
}

bool TinyMqttClient::subscribe(const char* topic) {
    return subscribe(topic, 0);
}

bool TinyMqttClient::subscribe(const char* topic, uint8_t qos) {
    size_t topicLength = strnlen(topic, this->bufferSize);
    if (topic == 0) 
        return false;
    
    if (qos > 1) 
        return false;
    
    if (this->bufferSize < 9 + topicLength) 
        return false;
    
    if (connected()) {
        uint16_t length = TINY_MQTT_MAX_HEADER_SIZE;
        nextMsgId++;
        if (nextMsgId == 0) {
            nextMsgId = 1;
        }
        this->buffer[length++] = (nextMsgId >> 8);
        this->buffer[length++] = (nextMsgId & 0xFF);
        length = writeString((char*)topic, this->buffer,length);
        this->buffer[length++] = qos;
        return write(TINY_MQTT_MESSAGE_TYPE_SUBSCRIBE << 4 | TINY_MQTT_QOS_1, this->buffer, length - TINY_MQTT_MAX_HEADER_SIZE);
    }
    return false;
}

bool TinyMqttClient::unsubscribe(const char* topic) {
	size_t topicLength = strnlen(topic, this->bufferSize);
    if (topic == 0) {
        return false;
    }
    if (this->bufferSize < 9 + topicLength) {
        // Too long
        return false;
    }
    if (connected()) {
        uint16_t length = TINY_MQTT_MAX_HEADER_SIZE;
        nextMsgId++;
        if (nextMsgId == 0) {
            nextMsgId = 1;
        }
        this->buffer[length++] = (nextMsgId >> 8);
        this->buffer[length++] = (nextMsgId & 0xFF);
        length = writeString(topic, this->buffer,length);
        return write(TINY_MQTT_MESSAGE_TYPE_UNSUBSCRIBE << 4 | TINY_MQTT_QOS_1, this->buffer, length - TINY_MQTT_MAX_HEADER_SIZE);
    }
    return false;
}

void TinyMqttClient::disconnect() {
    this->buffer[0] = TINY_MQTT_MESSAGE_TYPE_DISCONNECT << 4;
    this->buffer[1] = 0;
    _client->write(this->buffer,2);
    _state = TINY_MQTT_DISCONNECTED;
    _client->flush();
    _client->stop();
    lastInActivity = lastOutActivity = millis();
}

uint16_t TinyMqttClient::writeString(const char* string, uint8_t* buf, uint16_t pos) {
    const char* idp = string;
    uint16_t i = 0;
    pos += 2;
    while (*idp) {
        buf[pos++] = *idp++;
        i++;
    }
    buf[pos-i-2] = (i >> 8);
    buf[pos-i-1] = (i & 0xFF);
    return pos;
}

uint8_t TinyMqttClient::connected() {
    uint8_t rc;
    if (_client == NULL ) {
        rc = 0;
    } else {
        rc = (int)_client->connected();
        if (!rc) {
            if (this->_state == TINY_MQTT_CONNECTED) {
                this->_state = TINY_MQTT_CONNECTION_LOST;
                _client->flush();
                _client->stop();
            }
        } else {
            return this->_state == TINY_MQTT_CONNECTED;
        }
    }

    return rc;
}

void TinyMqttClient::setServer(uint8_t * ip, uint16_t port) {
    IPAddress addr(ip[0],ip[1],ip[2],ip[3]);
    setServer(addr,port);
}

void TinyMqttClient::setServer(IPAddress ip, uint16_t port) {
    this->ip = ip;
    this->port = port;
    this->domain = NULL;
}

void TinyMqttClient::setServer(const char * domain, uint16_t port) {
    this->domain = domain;
    this->port = port;
}

void TinyMqttClient::setCallback(TINY_MQTT_CALLBACK_SIGNATURE) {
    this->callback = callback;
}

void TinyMqttClient::setEventCallback(TINY_MQTT_EVENT_CALLBACK_SIGNATURE) {
    this->event_callback = event_callback;
}

void TinyMqttClient::setClient(Client& client){
    this->_client = &client;
}

int TinyMqttClient::state() {
    return this->_state;
}

bool TinyMqttClient::setBufferSize(uint16_t size) {
    if (size == 0) {
        // Cannot set it back to 0
        return false;
    }
    if (this->bufferSize == 0) {
        this->buffer = (uint8_t*)malloc(size);
    } else {
        uint8_t* newBuffer = (uint8_t*)realloc(this->buffer, size);
        if (newBuffer != NULL) {
            this->buffer = newBuffer;
        } else {
            return false;
        }
    }
    this->bufferSize = size;
    return (this->buffer != NULL);
}

uint16_t TinyMqttClient::getBufferSize() {
    return this->bufferSize;
}

void TinyMqttClient::setKeepAlive(uint16_t keepAlive) {
    this->keepAlive = keepAlive;
}

void TinyMqttClient::setSocketTimeout(uint16_t timeout) {
    this->socketTimeout = timeout;
}
