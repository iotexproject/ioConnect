- #### This example requires Linux to have libmicrohttpd installed.

​		On Debian based systems like `Ubuntu`, you can use the following command:

```bash
sudo apt-get update
sudo apt-get install libmicrohttpd-dev
```

​		On `CentOS` or `RHEL` systems, `libmicrohttpd` can be installed using the `yum` or `dnf` package manager:

```bash
sudo yum install libmicrohttpd-devel
```

​		On `Fedora` systems, `libmicrohttpd` can be installed using the `dnf` package manager:

```bash
sudo dnf install libmicrohttpd-devel
```

​		On `Arch` Linux systems, `libmicrohttpd` can be installed using the `pacman` package manager:

```bash
sudo pacman -S libmicrohttpd
```



- #### Copy the entire `core` and `pal` directory from the `SDK` directory to the current directory.

  ![core](./image/core.png)

- #### Enter to the `core/src/include/config` directory.

  ```
  cd ./core/src/include/config
  ```

- #### Rename `autoconfig_linux.h` to `autoconfig.h`.

  ```
  rm autoconfig.h
  cp autoconfig_linux.h autoconfig.h
  ```

- #### Create a `build` directory.

  ```
  cd ../../../../
  
  mkdir build
  ```

- #### Enter to the `build` directory.

  ```
  cd ./build
  ```

- #### Execute the command.

  ```
  cmake ..
  
  make
  ```

- #### Run the newly generated test program `DeviceRegister`.

  ```
  ./DeviceRegister
  ```

- #### After the program runs, you should see information similar to the following:

  ```bash
  My Sign DID :                   did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03
  My Key Agreement DID :          did:io:0x6246bb9b1df4a225dd2b68e0fa9d4f17ca2c6684
  DIDdoc :
  {
          "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
          "id":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03",
          "authentication":       ["did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03#Key-secp256k1-1"],
          "keyAgreement": ["did:io:0x6246bb9b1df4a225dd2b68e0fa9d4f17ca2c6684#Key-p256-2"],
          "verificationMethod":   [{
                          "id":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03#Key-secp256k1-1",
                          "type": "JsonWebKey2020",
                          "controller":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03",
                          "publicKeyJwk": {
                                  "crv":  "secp256k1",
                                  "x":    "jfaXFKMxRIvAxQAnd39tLX2S-9R382JLl4v28x_jEGY",
                                  "y":    "AlOIUkk7iykqkkcLlFa5Ceo38g_qdUYGiK_7uk69fYY",
                                  "kty":  "EC",
                                  "kid":  "Key-secp256k1-1"
                          }
                  }, {
                          "id":   "did:io:0x6246bb9b1df4a225dd2b68e0fa9d4f17ca2c6684#Key-p256-2",
                          "type": "JsonWebKey2020",
                          "controller":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03",
                          "publicKeyJwk": {
                                  "crv":  "P-256",
                                  "x":    "dOIY64rAS3gI0ljObGgtHZvXSn1rzyZJr512yUFINQE",
                                  "y":    "zs07XzmLKKXUmeRs-dEmdzPz4W5sb-OtEpdmi-10S8U",
                                  "kty":  "EC",
                                  "kid":  "Key-p256-2"
                          }
                  }]
  }
  Upload DID : {
          "did":  "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03",
          "puk":  "0x8df69714a331448bc0c50027777f6d2d7d92fbd477f3624b978bf6f31fe3106602538852493b8b292a92470b9456b909ea37f20fea75460688affbba4ebd7d86",
          "project_name": "Linux_Simulator",
          "signature":    "3543a4f141a61e5727a8843c6553ffe7092362c6aa61339fffeabe23d6c2ab0e585e0d23e04164d7bcee5a6949b188c695937b6a4548d811489ed09dc13ea8b3"
  }
  Upload DIDDoc : {
          "diddoc":       {
                  "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
                  "id":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03",
                  "authentication":       ["did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03#Key-secp256k1-1"],
                  "keyAgreement": ["did:io:0x6246bb9b1df4a225dd2b68e0fa9d4f17ca2c6684#Key-p256-2"],
                  "verificationMethod":   [{
                                  "id":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03#Key-secp256k1-1",
                                  "type": "JsonWebKey2020",
                                  "controller":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03",
                                  "publicKeyJwk": {
                                          "crv":  "secp256k1",
                                          "x":    "jfaXFKMxRIvAxQAnd39tLX2S-9R382JLl4v28x_jEGY",
                                          "y":    "AlOIUkk7iykqkkcLlFa5Ceo38g_qdUYGiK_7uk69fYY",
                                          "kty":  "EC",
                                          "kid":  "Key-secp256k1-1"
                                  }
                          }, {
                                  "id":   "did:io:0x6246bb9b1df4a225dd2b68e0fa9d4f17ca2c6684#Key-p256-2",
                                  "type": "JsonWebKey2020",
                                  "controller":   "did:io:0x39e0730c36c7683cb705585d8a8dcc2787a26b03",
                                  "publicKeyJwk": {
                                          "crv":  "P-256",
                                          "x":    "dOIY64rAS3gI0ljObGgtHZvXSn1rzyZJr512yUFINQE",
                                          "y":    "zs07XzmLKKXUmeRs-dEmdzPz4W5sb-OtEpdmi-10S8U",
                                          "kty":  "EC",
                                          "kid":  "Key-p256-2"
                                  }
                          }]
          },
          "signature":    "3543a4f141a61e5727a8843c6553ffe7092362c6aa61339fffeabe23d6c2ab0e585e0d23e04164d7bcee5a6949b188c695937b6a4548d811489ed09dc13ea8b3"
  }
  HTTP server running on port 8000
  ```

- #### Please visit the following website to register your device：

​		[IoTeX Hub (iotex-hub-pr-11.onrender.com)](https://iotex-hub-pr-11.onrender.com/device-registration)
