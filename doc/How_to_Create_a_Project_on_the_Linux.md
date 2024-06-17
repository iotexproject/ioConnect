# How to Create a Project on the Linux

​		The ioConnect SDK supports compilation in a Linux environment. The SDK uses CMake to generate the Makefile required for compilation, so your Linux system needs to have the latest CMake tool and the necessary GCC toolchain installed.



## Preparation

### Installing the GCC Compiler Toolchain (Skip if already installed)

- Below is a basic installation example suitable for most Debian-based distributions (such as **Ubuntu**):


```bash
sudo apt update
sudo apt install build-essential
```

- For Red Hat-based distributions (such as **CentOS** or **Fedora**), you can use the following command:


```bash
sudo yum groupinstall 'Development Tools'
```

- Or for newer versions, such as **Fedora**:


```bash
sudo dnf groupinstall 'Development Tools'
```

These commands will install the GCC compiler and some other common compilation tools, such as make and automake.

After installation, you can check if GCC is correctly installed by running the command `gcc -v`.

```bash
Using built-in specs.
COLLECT_GCC=gcc
COLLECT_LTO_WRAPPER=/usr/libexec/gcc/x86_64-linux-gnu/13/lto-wrapper
OFFLOAD_TARGET_NAMES=nvptx-none:amdgcn-amdhsa
OFFLOAD_TARGET_DEFAULT=1
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion='Ubuntu 13.1.0-8ubuntu1~22.04' --with-bugurl=file:///usr/share/doc/gcc-13/README.Bugs --enable-languages=c,ada,c++,go,d,fortran,objc,obj-c++,m2,rust --prefix=/usr --with-gcc-major-version-only --program-suffix=-13 --program-prefix=x86_64-linux-gnu- --enable-shared --enable-linker-build-id --libexecdir=/usr/libexec --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --enable-bootstrap --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-plugin --enable-default-pie --with-system-zlib --enable-libphobos-checking=release --with-target-system-zlib=auto --enable-objc-gc=auto --enable-multiarch --disable-werror --enable-cet --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-offload-targets=nvptx-none=/build/gcc-13-IvzKaI/gcc-13-13.1.0/debian/tmp-nvptx/usr,amdgcn-amdhsa=/build/gcc-13-IvzKaI/gcc-13-13.1.0/debian/tmp-gcn/usr --enable-offload-defaulted --without-cuda-driver --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu --with-build-config=bootstrap-lto-lean --enable-link-serialization=2
Thread model: posix
Supported LTO compression algorithms: zlib zstd
gcc version 13.1.0 (Ubuntu 13.1.0-8ubuntu1~22.04)
```



### Installing CMake Tool (Skip if already installed)

Installing CMake on Linux can usually be done via the package manager. Below are the installation commands for some common Linux distributions:

- For Debian-based systems (such as **Ubuntu**):


```bash
sudo apt-update
sudo apt-get install cmake
```

- For Red Hat-based systems (such as **Fedora** or **CentOS**):


```bash
sudo yum install cmake
```

- For **Fedora** (using dnf instead of yum):


```bash
sudo dnf install cmake
```

- For **Arch Linux**:


```bash
sudo pacman -S cmake
```

- For **openSUSE**:


```bash
sudo zypper install cmake
```

After installation, you can check if CMake is correctly installed by running `cmake --version`.

```bash
cmake version 3.22.1

CMake suite maintained and supported by Kitware (kitware.com/cmake).
```



## Compiling the Project

- #### Copy the entire `core` directory from the `SDK` directory to the your workspace.

- #### Enter to the `core/src/include/config` directory.

  ```bash
  cd ./core/src/include/config
  ```

- #### Rename `autoconfig_linux.h` to `autoconfig.h`.

  ```bash
  rename autoconfig_linux.h autoconfig.h
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
  cmake ..
  
  make
  ```

  

#### 		After compilation, a dynamically linked library `ioConnectCore.so` will be automatically generated in the `build` directory.



## Example

​		We provide an example of the ioConnect SDK on the Linux in the `example/linux` directory.