# How to Create a Project on the Windows

​		The ioConnect SDK supports compilation in a Windows environment. The SDK uses CMake to generate the Makefile required for compilation, so your Windows system needs to have the latest CMake tool and the necessary GCC toolchain installed.



## Preparation

### Installing the GCC Compiler Toolchain (Skip if already installed)

​		Installing GCC on Windows usually involves two methods: using an online installer (such as MinGW) or using a full Cygwin installation that includes GCC. Below are the brief steps for installing GCC using MinGW:

- Visit the MinGW official website or use a search engine to search for “MinGW” to download the latest version of the installer.

- After downloading, run the installer.

- In the installation wizard, select the desired configuration options:

  - Operating System type (usually 'win32')

  - Architecture (e.g., 'i686' for 32-bit systems, 'x86_64' for 64-bit systems)

  - Thread model (usually choose 'posix')

  - Language (select the languages you need support for, such as C, C++)

  - Download and install the necessary packages.

- After completing the configuration, follow the on-screen instructions to proceed with the installation.

- Once the installation is complete, verify that GCC is correctly installed by entering `gcc --version` in the command line interface (such as CMD or PowerShell).

​		Example code (in the command line interface):

```bash
mingw-w64.exe --quiet-update
mingw-w64.exe -i
gcc --version
```

​		Please note that if you choose to use the online installer, you may need to ensure that your computer can access the Internet and have some network setup knowledge to handle proxy servers and other issues. If your network environment does not allow direct Internet access, you may need to use alternative methods, such as downloading the installation packages via an internal company network and performing a local installation.



### Installing CMake Tool (Skip if already installed)

​		Installing CMake on Windows can usually be done by downloading the executable installer from the official website.

- Download the executable installer from:

​		https://cmake.org/download/

- Select the “Windows Win64 Installer” (or the corresponding 32-bit version) for download.

- After downloading, run the installer and follow the prompts to complete the installation.

- Once the installation is complete, you can check if CMake is correctly installed by entering `cmake --version` in the command line interface.

​		Example code (in the command line interface):

```bash
cmake --version
```



## Compiling the Project

- #### Copy the entire `core` directory from the `SDK` directory to the your workspace.

- #### Enter to the `core/src/include/config` directory.

  ```bash
  cd ./core/src/include/config
  ```

- #### Rename `autoconfig_linux.h` to `autoconfig.h`.

  ```bash
  rename autoconfig_windows.h autoconfig.h
  ```

- #### Create a `build` directory.

  ```bash
  cd ../../../../
  
  mkdir build
  ```

- #### Enter to the `build` directory.

  ```bash
  cd ./build
  ```

- #### Execute the command.

  ```bash
  cmake -G "MinGW Makefiles" ..
  
  make
  ```

  

#### 		After compilation, a dynamically linked library `ioConnectCore.so` will be automatically generated in the `build` directory.



## Example

​		TBC