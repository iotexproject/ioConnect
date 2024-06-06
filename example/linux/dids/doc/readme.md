- #### Copy the entire `core` directory from the `SDK` directory to the current directory.

  ![core](.\image\core.png)

- #### Enter to the `core/src/include/config` directory.

  ```
  cd ./core/src/include/config
  ```

- #### Rename `autoconfig_linux.h` to `autoconfig.h`.

  ```
  rename autoconfig_linux.h autoconfig.h
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

- #### Run the newly generated test program `DIDComm_Server`.

  ```
  ./DIDComm_Server
  ```

  

