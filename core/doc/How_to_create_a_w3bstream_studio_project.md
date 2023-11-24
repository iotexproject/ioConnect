

# How to create a w3bstream studio project



This article will explain how to create projects, add devices, get token, mqtt topic and other information through w3bstream studio.

For more information about w3bstream, please refer to the following document:

[About W3bstream - W3bstream Docs](https://docs.w3bstream.com/introduction/readme)



## Login to w3bstream studio

[W3bstream Devnet](https://devnet-staging.w3bstream.com/)

##### After login：

<p>
  <img src="img\devnet_home.png" alt="devnet_home">
</p>



## Create a new project

##### 1. Please click the Create a project now button to start creating a new project.

<p>
  <img src="img\devnet_new_prj.png" alt="devnet_new_prj">
</p>

##### 2. Enter a project name in the Name text box.

**Note: The project name should be less than 16 characters.**

You can choose either **Hello World** or **Code Upload**. (Here we choose Hello World as a demo)

<p>
  <img src="img\devnet_new_prj_2.png" alt="devnet_new_prj_2">
</p>

When the settings are complete, click the Submit button. We now have a project named "esp32_hello".

<p>
  <img src="img\devnet_home_prj.png" alt="devnet_home_prj">
</p>


## Add a device and get the Token

##### 1. Click on the project name (esp32_hello) to enter this project.

##### 2. Please click Devices and Add Device in order.

<p>
  <img src="img\devnet_prj_adddev.png" alt="devnet_prj_adddev">
</p>

##### 3. Enter the Publisher Key.

<p>
  <img src="img\devnet_prj_adddev_2.png" alt="devnet_prj_adddev_2">
</p>

**Device has been added and Token is displayed.**

<p>
  <img src="img\devnet_prj_adddev_3.png" alt="devnet_prj_adddev_3">
</p>




## Get the Topic of MQTT

<p>
  <img src="img\devnet_prj_mqtt_topic.png" alt="devnet_prj_mqtt_topic">
</p>

**You can see the MQTT Publish Topic after clicking on Triggers on the left**



## View WASM log output

<p>
  <img src="img\devnet_log.png" alt="devnet_log">
</p>
