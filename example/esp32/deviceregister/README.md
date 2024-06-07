| Supported Targets | ESP32-S3 |
| ----------------- | -------- |

# Device Register Example

This example shows how to use the device register of the ioConnect SDK  for registering to the IoTeX .



## What this example does

- Generate a JWK with a lifetime of persist for the device.
- Generate the device's DID based on this JWK.
- Generate the device’s DIDdoc based on this JWK and DID.
- Communicates with https://web-wallet-v2.onrender.com/ioid and automatically completes device registration.



## How to use example

### Configure the project

Open the project configuration menu (`idf.py menuconfig`).

In the `Example Configuration` menu:

- Set the Wi-Fi configuration.
  - Set `WiFi SSID`.
  - Set `WiFi Password`.

Optional: If you need, change the other options according to your requirements.

### Build and Flash

Build the project and flash it to the board, then run the monitor tool to view the serial output:

Run `idf.py -p PORT flash monitor` to build, flash and monitor the project.

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for all the steps to configure and use the ESP-IDF to build projects.

* [ESP-IDF Getting Started Guide on ESP32](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)

* [ESP-IDF Getting Started Guide on ESP32-S2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/get-started/index.html)

* [ESP-IDF Getting Started Guide on ESP32-C3](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/get-started/index.html)

  

## Example Output
Note that the output, in particular the order of the output, may vary depending on the environment.

Console output if station connects to AP successfully:
```
I (589) wifi station: ESP_WIFI_MODE_STA
I (599) wifi: wifi driver task: 3ffc08b4, prio:23, stack:3584, core=0
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (629) wifi: wifi firmware version: 2d94f02
I (629) wifi: config NVS flash: enabled
I (629) wifi: config nano formating: disabled
I (629) wifi: Init dynamic tx buffer num: 32
I (629) wifi: Init data frame dynamic rx buffer num: 32
I (639) wifi: Init management frame dynamic rx buffer num: 32
I (639) wifi: Init management short buffer num: 32
I (649) wifi: Init static rx buffer size: 1600
I (649) wifi: Init static rx buffer num: 10
I (659) wifi: Init dynamic rx buffer num: 32
I (759) phy: phy_version: 4180, cb3948e, Sep 12 2019, 16:39:13, 0, 0
I (769) wifi: mode : sta (30:ae:a4:d9:bc:c4)
I (769) wifi station: wifi_init_sta finished.
I (889) wifi: new:<6,0>, old:<1,0>, ap:<255,255>, sta:<6,0>, prof:1
I (889) wifi: state: init -> auth (b0)
I (899) wifi: state: auth -> assoc (0)
I (909) wifi: state: assoc -> run (10)
I (939) wifi: connected with #!/bin/test, aid = 1, channel 6, BW20, bssid = ac:9e:17:7e:31:40
I (939) wifi: security type: 3, phy: bgn, rssi: -68
I (949) wifi: pm start, type: 1

I (1029) wifi: AP's beacon interval = 102400 us, DTIM period = 3
I (2089) esp_netif_handlers: sta ip: 192.168.77.89, mask: 255.255.255.0, gw: 192.168.77.1
I (2089) wifi station: got ip:192.168.77.89
I (2089) wifi station: connected to ap SSID:myssid password:mypassword

JWK[Sign] : 
{
        "crv":  "secp256k1",
        "x":    "KAkqUSARxKvyrfkykUH9fl5Ef6AbcaoEWQgi8IwFdIo",
        "y":    "dmlXLytvKgIVH4hgPP2Tzlp6dJbq5KWtluiX1U1v9o0",
        "kty":  "EC",
        "kid":  "Key-secp256k1-1"
}
JWK[KA] : 
{
        "crv":  "P-256",
        "x":    "WIbBzvEz-6beOyvZtVmtN9J1EvPlgKUPDTPZy3kJJnk",
        "y":    "OvsnblaTwctIM2tP3pu8kh2RxpXxIwwtNceM4Z9iKcI",
        "kty":  "EC",
        "kid":  "Key-p256-2"
}
DID :
did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73
DIDdoc [1125] :
{
        "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
        "id":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73",
        "authentication":       ["did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73#Key-secp256k1-1"],
        "keyAgreement": ["did:io:0xfab99326ce27d0d30b8609e6d4d748629242b077#Key-p256-2"],
        "verificationMethod":   [{
                        "id":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73#Key-secp256k1-1",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73",
                        "publicKeyJwk": {
                                "crv":  "secp256k1",
                                "x":    "KAkqUSARxKvyrfkykUH9fl5Ef6AbcaoEWQgi8IwFdIo",
                                "y":    "dmlXLytvKgIVH4hgPP2Tzlp6dJbq5KWtluiX1U1v9o0",
                                "kty":  "EC",
                                "kid":  "Key-secp256k1-1"
                        }
                }, {
                        "id":   "did:io:0xfab99326ce27d0d30b8609e6d4d748629242b077#Key-p256-2",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xba80b710f0c27c8b3b72df63861e2ecea9c5aa73",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "WIbBzvEz-6beOyvZtVmtN9J1EvPlgKUPDTPZy3kJJnk",
                                "y":    "OvsnblaTwctIM2tP3pu8kh2RxpXxIwwtNceM4Z9iKcI",
                                "kty":  "EC",
                                "kid":  "Key-p256-2"
                        }
                }]
}
```

Console output if the station failed to connect to AP:
```
I (589) wifi station: ESP_WIFI_MODE_STA
I (599) wifi: wifi driver task: 3ffc08b4, prio:23, stack:3584, core=0
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (629) wifi: wifi firmware version: 2d94f02
I (629) wifi: config NVS flash: enabled
I (629) wifi: config nano formating: disabled
I (629) wifi: Init dynamic tx buffer num: 32
I (629) wifi: Init data frame dynamic rx buffer num: 32
I (639) wifi: Init management frame dynamic rx buffer num: 32
I (639) wifi: Init management short buffer num: 32
I (649) wifi: Init static rx buffer size: 1600
I (649) wifi: Init static rx buffer num: 10
I (659) wifi: Init dynamic rx buffer num: 32
I (759) phy: phy_version: 4180, cb3948e, Sep 12 2019, 16:39:13, 0, 0
I (759) wifi: mode : sta (30:ae:a4:d9:bc:c4)
I (769) wifi station: wifi_init_sta finished.
I (889) wifi: new:<6,0>, old:<1,0>, ap:<255,255>, sta:<6,0>, prof:1
I (889) wifi: state: init -> auth (b0)
I (1889) wifi: state: auth -> init (200)
I (1889) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (1889) wifi station: retry to connect to the AP
I (1899) wifi station: connect to the AP fail
I (3949) wifi station: retry to connect to the AP
I (3949) wifi station: connect to the AP fail
I (4069) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (4069) wifi: state: init -> auth (b0)
I (5069) wifi: state: auth -> init (200)
I (5069) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (5069) wifi station: retry to connect to the AP
I (5069) wifi station: connect to the AP fail
I (7129) wifi station: retry to connect to the AP
I (7129) wifi station: connect to the AP fail
I (7249) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (7249) wifi: state: init -> auth (b0)
I (8249) wifi: state: auth -> init (200)
I (8249) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (8249) wifi station: retry to connect to the AP
I (8249) wifi station: connect to the AP fail
I (10299) wifi station: connect to the AP fail
I (10299) wifi station: Failed to connect to SSID:myssid, password:mypassword
```

## Troubleshooting

For any technical queries, please open an [issue](https://github.com/machinefi/ioConnect/issues) on GitHub. We will get back to you soon.
