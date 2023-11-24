## **DeviceConnect SDK: Key Enabler for Connecting Smart Devices to Web3**

### **Introduction**

The IoTeX DeviceConnect SDK (referred to as SDK) is a software development toolkit for Internet of Things (IoT) applications. It aims to facilitate the rapid and convenient transformation of traditional Web2 projects into Web3 ones. The SDK provides the necessary components for traditional IoT projects to transition into the Web3 domain, including salient features such as compliance with the PSA crypto APIs certified by Arm, decentralized identifiers (DIDs), verifiable credentials (VCs), and DIDComm messaging. Users can easily integrate their existing or ongoing traditional IoT projects with Web3 using this SDK. Moreover, the SDK is compatible with a wide range of embedded systems with minimal code coupling.

#### **Design Methodology and Architecture**

![SDK_Design_Overall](doc/image/SDK_Design_Overall.png)

The SDK adopts a layered design and consists of five layers from top to bottom, namely the DIDComm messaging layer, the identity and credential service layer, the cryptographic service layer, the cryptographic primitive layer, and the root of trust layer. It is worth noting that each layer is composed of multiple components, allowing developers to customize the SDK to meet hardware limitations and application requirements.

The arrows on the right side of the architecture diagram represent two development directions defined by the SDK. The southern part forms the core framework of the entire SDK, which is based on the cryptographic suite developed in compliance with Arm’s Platform Security Architecture (PSA) architecture and aims to provide unified, standardized cryptographic suite application programing interfaces (APIs) for northbound component developers or other application developers. Through highly abstracted driver interfaces, cryptographic suites suitable for various development platforms, and an optimized SDK configuration system, the underlying southern layer not only applies to a wide range of embedded system platforms but also greatly reduces the learning curve for developers using the SDK.

The northern part is composed of self-sovereign identity (SSI) components built upon the core framework mentioned above. The DIDs, VCs and DIDComm messaging represent the three key pillars of SSI, which aim to move control of digital identity from conventional identity providers to individuals and lay down the foundation for people, organizations and things establishing rich digital relationships. DIDs are a new type of globally unique identifier (URI) that enables verifiable, self-sovereign digital identity, whereas VCs are able to attest identity attributes of subjects and the exchange of VCs builds up trust among DID-identified peers. Both DIDs and VCs are the proposed recommendations of the World Wide Web Consortium (W3C). DIDComm, as specified by the Decentralized Identity Foundation (DIF), provides utility for people, organizations and IoT devices interacting with machine-readable messages and creating DIDbased relationships. DIDComm messages are exchanged between software agents of entities for implementing a variety of security protocols.

The modular design methodology allows developers to easily configure the SDK to adapt to their project needs. For instance, developers can build hardware wallets or blockchain embedded clients based on the southbound core framework, and create machine-to-machine (M2M) communications, identity wallets, metaverse applications, etc., based on the northbound SSI components. In the future, the SDK will continue to evolve and provide other application components related to Web3 and blockchain domains for developers to use.

For a more technical introduction to the SDK, please refer to: https://github.com/machinefi/web3-iot-sdk.



### **Significance of the SDK**

The significance of this SDK in the IoT industry is significant and can be summarized in the following aspects:

#### **Compatibility with a wide range of embedded devices**

Currently, there are numerous traditional Web2 projects in the market, which have certain limitations in terms of functionality and technology. Web3 projects, on the other hand, offer a number of advantages, such as decentralization, data transparency, and smart contracts. However, the IoT field involves a vast number of embedded devices, including various chip architectures (e.g., Arm, MIPS, RISC-V, etc.) and chips from different manufacturers. Supporting these diverse and massive devices remains a significant challenge. Development teams often face major technical hurdles, such as:

- Inability to find suitable Web3 development kits that support their development platforms

- Different development platforms adopting different Web3 development kits, leading to increased learning and development costs for developers and decreased code reusability for existing projects


From the very beginning, the SDK was designed to address these challenges. By employing a mechanism-based core framework and a strategy-based platform adaptation layer (PAL) design, the SDK is able to provide support for a wide range of embedded systems. The core framework abstracts stable and mechanistic functionalities such as platform-independent encryption algorithms, communication details, data encoding/decoding, etc., while the platform adaptation layer adapts to different embedded systems and vibrant embedded community requirements (such as Arduino, ESP32, Raspberry Pi, Nordic, STM32, etc.), placing the differences in platform-specific functionalities within the platform device layer. Through this design, the SDK can easily adapt to different chip architectures and devices, greatly reducing the development complexity and learning curve.

#### **Smooth transition from Web2 to Web3**

Traditional Web2 projects with highly centralized architectures dominate the IoT field. However, with the rise of blockchain technology, Web3 and DePIN projects offer more advantages. More and more developers want to enter this emerging field and connect their existing projects to decentralized W3bStream node networks, unlocking the trillion-dollar machine economy. However, the typical process of transforming existing Web2 projects into Web3 projects involves tedious re-design and re-development, posing a major challenge for developers.

The significance of this SDK lies in its ability to smoothly transition existing Web2 projects to the Web3 platform without the need for redesign or redevelopment. By providing a core framework and a platform adaptation layer (PAL), the SDK simplifies the integration process of Web3 technologies. Developers only need to make minor code modifications to connect their existing IoT projects to the W3bStream node network, saving significant development time and cost. Furthermore, to minimize code coupling with the original project, the SDK introduces the concept of a standard layer. Developers and the SDK default to using the common framework provided by the standard layer, enabling seamless integration of the SDK into existing project codebases.

#### **Enhanced data security and trustworthiness**

With the rapid development of the IoT, data security and trustworthiness have become essential in the IoT field. The security of embedded systems’ applications and data is becoming increasingly prominent. Unfortunately, building a complete and reliable security system is a significant challenge for embedded engineers who are not familiar with security. However, Web3 technologies such as blockchain, smart contracts, and decentralized identity verification offer better choices for embedded engineers and IoT projects.

The SDK fully complies with ARM’s PSA cryptographic framework, providing advanced encryption and decryption capabilities to protect the communication and data of IoT devices. The introduction of blockchain technology ensures data integrity and immutability, with every data transaction recorded on an immutable blockchain. By using this SDK, developers can easily connect their devices to the W3bStream node network. Their subsequent development of DApps can achieve higher data security and traceability, enhancing their ability to resist malicious attacks and data tampering.



### **Innovative Technological Features**

The IoTex DeviceConnect SDK represents a leading position in the industry due to the following innovative technological features:

#### **Compatibility with a wide range of embedded hardware**

It is well-known that embedded development is not only challenging due to the complexity of programming languages (C/C++), but also due to the complexity and diversity of system architectures, compile environments, and supporting components.

![Embedded](.\Doc\image\Embedded.png)

From the figure above, the left circles represent some of the design factors that embedded software engineers need to consider when designing IoT projects (only listing a few examples). Each factor contains numerous subcategories for developers to choose from, indicating the complexity that embedded software engineers face. On the right side, it represents the current development direction in the embedded field, which is moving towards consolidation and unification. For example, in the process of chip development, ARM has proposed and designed the CMSIS standard framework to unify the diverse types of ARM chips (SoCs) on the market. Similarly, OpenHarmony aims to unify the chaotic situation in the entire embedded operating system. Each black wireframe in the diagram simply represents the difficulties encountered during the unification process.

Based on the above, a qualified embedded engineer or an excellent IoT project needs to consider many aspects, such as:

- Selecting the appropriate IoT chip based on project requirements and development costs.

- Familiarity with the corresponding development toolchain.

- Choosing whether to use an embedded operating system and selecting the specific one.

- Identifying the development components required by the project.


![Embeded_heirarchy](.\Doc\image\Embeded_heirarchy.png)

The development focus has shifted from initially independent hardware drivers (represented by register-based operations) to chip manufacturers integrating their products into development libraries (represented by STM32’s Standard Peripherals Firmware Library), and finally to the current development of active community frameworks and large chip manufacturers’ SDKs (represented by Raspberry Pi, Arduino, ESP32, etc.). Overall, embedded and IoT development is moving towards convergence.

![PAL](.\Doc\image\PAL.png)

This SDK aims to support a wide range of embedded systems, not limited to specific device types. Therefore, the SDK takes a higher-level perspective and, through its unique core framework and platform adaptation layer (PAL) structure, adapts to different chip architectures and device designs.

The core framework abstracts stable functionalities that are independent of the development platform or environment. It forms the foundation of the entire SDK. The platform adaptation layer adapts to different embedded systems and communities, differentiating the specific functionalities of each platform. For example, different communities have significant differences in MQTT implementations. Arduino tends to use C++ classes, while the ESP32 community prefers traditional API implementation styles. Both communities have significant differences in MQTT implementation and usage. However, the SDK adapts to the implementation methods of each community, including the community’s compilation rules, coding conventions, framework designs, etc., adhering to the SDK PAL standard.

Each PAL component revolves around the core framework, which provides the following advantages:

- With support and adaptation from active communities, the SDK can support a wider range of IoT hardware. For example, the SDK currently supports the Arduino community, and in theory, any hardware platform supported by Arduino can be supported by the SDK.

- Reduces the development complexity and cycle of the entire SDK. After testing and verification, the platform adaptation layer code for each community is limited to around 300 to 500 lines.

- Developers can quickly and conveniently add new hardware platforms. When developers encounter unsupported embedded hardware while using the SDK, they can develop new PAL components according to the SDK PAL standard, requiring only about 300 lines of code.


It is important to note that PAL component code not only needs to adapt to the community’s code framework system but also needs to support the community’s default or specified file structure, compilation standards, and more. For example, the development projects of Arduino and ESP32 have completely different programming languages, reference paths, and library managers.

Based on the above information, the unique core framework and PAL layer design can effectively solve the device compatibility issues in IoT projects and provide developers with a user-friendly development and usage environment.

#### **Minimal code coupling**

Another feature of this SDK is its assumption that users have already developed or are developing a traditional Web2 IoT project. When developers or development teams want to transform their Web2 project into Web3, they face several challenges:

- Code reuse: Maximizing the reuse of developed functional components or the entire project.

- Minimal code coupling: Not making extensive modifications to the original code due to the introduction of new component libraries.


Web3 technologies cover a broad range and can be complex. The SDK achieves minimal code coupling by compressing and streamlining the technology stack, reducing complexity to a minimum. Additionally, the SDK introduces the concept of a standard layer to reduce code coupling between the SDK and the original project.

![Standard Layer](.\Doc\image\Standard Layer.png)

Traditional component usage employs the API pattern shown above: each independently designs API functions, which are then referenced and called by both sides. However, this approach inevitably leads to some issues:

**Both parties must have a clear understanding of each other’s API functions, including their definitions and usage methods, before usage.**

The SDK breaks away from the traditional API call mechanism by introducing a standard layer (as shown at the bottom of the figure). The standard layer uses well-known design frameworks, such as active embedded operating systems (e.g., FreeRTOS, Zephyr), POSIX standards, and active community code frameworks (e.g., Arduino, Raspberry Pi, ESP32). Both developers and the SDK default to using the common framework provided by the standard layer, which allows for seamless integration with minimal knowledge of the technical details of the other party’s standard layer.

For example, let’s consider the event handling process in the ESP32 community:

![norm api](.\Doc\image\norm api.png)

Suppose a Web2 project needs to send data to a W3Bstream node. The traditional handling process would involve the following steps:

- Include the SDK’s header files.


- Find the API function for sending data to the W3Bstream node through documentation or examples (e.g., Send_Data(char \*buffer, uint buf_len, int data_type)).

- Understand the usage of the API, including function parameters, return values, and operating mechanisms (e.g., synchronous/asynchronous).

With the introduction of the standard layer, the handling process becomes as follows:

![SL_Handler](.\Doc\image\SL_Handler.png)

- The original data flow of the Web2 project involves obtaining data from a sensor and sending an event to the ESP32 event handler, which is then routed to the data handler of the Web2 project for asynchronous and multithreaded processing.

- The SDK subscribes to the same event, and when the ESP32 event handler routes this event, it also routes the event to the SDK’s data handler.

- When the SDK receives the event, it processes the data in its own thread and sends it to the W3bstream. At this point, the Web2 project is unaware of the SDK’s data processing flow.

- The use of the standard layer offers several advantages:

- The original data processing logic of the Web2 project remains unchanged.

- The Web2 project does not need to understand the data processing flow and specific details of the SDK.

- The Web2 project does not need to include files related to the SDK’s data processing.


In conclusion, the SDK’s innovative technological details represent a leading position in the industry. By providing compatibility with a wide range of embedded hardware, minimal code coupling, and seamless transition from Web2 to Web3, the SDK offers a convenient and efficient solution for the IoT industry. It significantly reduces development complexity and learning costs, enabling IoT developers to effortlessly apply Web3 technologies and seamlessly integrate IoT with the W3bstream node network.



### **Current Development Status**

#### **Supported Active Communities**

![support](.\Doc\image\support.png)

The SDK is currently supported by the active communities shown in the figure above. It has been submitted to the Arduino and ESPRESSIF communities and passed their component approval processes.

[PSACrypto - Arduino Libraries](https://www.arduinolibraries.info/libraries/psa-crypto)

[IDF Component Registry (espressif.com)](https://components.espressif.com/components?q=iotex)

#### **Industry Certification**

The IoTeX's PSACrypto is a cryptographic library (the southen part of SDK) that supports a wide range of embedded devices with flash memory from as low as 20KB to several hundred MB. It is fully compliant with the Arm PSA Certified Crypto API 1.1 standard. With its unique frontend and backend design, it allows users to choose a backend cryptographic library that best suits their needs, thereby achieving a good balance between the performance and memory footprint. Moreover, an optimized visual configuration tool provides great flexibility for developers to customize a cryptographic library based on the available hardware resources and specific project requirements and facilitates developers to integrate the PSACrypto library into their projects seamlessly.

![Core](.\Doc\image\Core.png)

The SDK has obtained the PSA Certified Crypto API label.

[IoTeX PSA Crypto \| PSA Certified](https://www.psacertified.org/products/iotex-psa-crypto/)

![psacertified](.\Doc\image\psacertified.jpg)



### **Future Plans**

#### **Support for a wider range of hardware and embedded communities**

The team plans to support the Zephyr embedded operating system and its development community.

#### **More Web3-related component support**

The team is currently developing the DIDComm component and plans to provide additional application components related to Web3 and blockchain in future iterations.
