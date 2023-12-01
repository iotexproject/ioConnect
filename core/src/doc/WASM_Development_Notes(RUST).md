# WASM Development Notes -- RUST Edition



## Getting Started

### RUST environment setup

Please follow the instructions in the [Rust Programming Language (rust-lang.org)](https://www.rust-lang.org/) documentation to install the development environment for RUST.

### WASM Environment Setup

##### Install wasm-pack with the following command

```
cargo install wasm-pack --no-default-features
```

##### Check if wasm32-wasi target is supported

```
rustup target list
```

##### If the wasm32-wasi target is not supported please use the following command to install it

```
rustup target add wasm32-wasi
```



## Compile

##### When WASM development is complete, it can be compiled using the following command, which will generate wasm files in the target\wasm32-wasi\release directory upon successful compilation.

```
cargo build --target=wasm32-wasi --release
```

##### To use the w3bstream SDK, enter the following command to add a dependency on ws-sdk.

```
cargo add ws-sdk
```



## Example

##### We will illustrate the development process of WASM based on the RUST language with an example:

This example demonstrates a multi-event handling development approach by providing two event handling functions:

- The **start** event handler corresponds to the VERIFY event, which is used to parse the data reported by the device side, read the public key and verify the signature uploaded by the device side;
- The **start_pk** event handler corresponds to the PUBKEY event, which is used to parse the data reported by the device side and save the public key uploaded by the device side.

##### Create a wasm lib

```
cargo new test-wasm --lib
```

##### Enter the test-wasm directory

```
cd test-wasm
```

##### Add ws-sdk dependency

```
cargo add ws-sdk
```

##### Modify the Cargo.toml file to set the crate-type to "cdylib"

```
[lib]
crate-type = ["cdylib"]
```

##### Modify Cargo.toml file to add dependent libraries

```
[dependencies]
ws-sdk =  { version = "0.1.15", features = ["crypto"]}
anyhow = "1.0.69"
serde_json = "1.0.93"
serde = { version = "1.0.152", features = ["derive"] }
hex = "0.4.3"
```

Write the code by copying the following code into the lib.rs file:

```rust
use anyhow::Result;
use serde_json::Value;
use ws_sdk::log::log_info;
use ws_sdk::stream::*;
use ws_sdk::crypto::{self, *};
use ws_sdk::database::kv::*;

#[no_mangle]
pub extern "C" fn start(rid: i32) -> i32 {  

    match handle(rid) {
		Ok(_) => return 0,
		_ => return -1,
    };
}

#[no_mangle]
pub extern "C" fn start_pk(rid: i32) -> i32 { 
    
	match handle_pk(rid) {
		Ok(_) => return 0,
		_ => return -1,
    };
}

fn handle(rid: i32) -> Result<()> {

    let data = String::from_utf8(get_data(rid as _)?)?;
	let message = String::from("iotex_sample");
	let payload: Value  = serde_json::from_str(&data)?;
	let sign = payload["sign"].as_str().unwrap();
	let pubkey = get("pub_key")?;
	let pubkey_str = String::from_utf8(pubkey)?;
	let pubkey_hex = hex::encode(&crypto::secp256r1::pubkey(&pubkey_str)?);

	assert!(crypto::secp256r1::verify(&pubkey_hex, message.as_bytes(), sign).is_ok());

	Ok(()) 
}

fn handle_pk(rid: i32) -> Result<()> {

    let data = String::from_utf8(get_data(rid as _)?)?;
	let payload: Value  = serde_json::from_str(&data)?;
	let pubk = payload["pubkey"].as_str().unwrap();
    
	set("pub_key", pubk.as_bytes().to_vec())?;
    
    Ok(())
}
```



##### Event Rounting Settings

<p>
  <img src="img\event_rounting.png" alt="event_rounting">
</p>

##### For more details about w3bstream studio, please check the following links:

[About W3bstream - W3bstream Docs](https://docs.w3bstream.com/introduction/readme)



## Reference example

##### For more examples of the w3bstream SDK, please see the following links:

[w3bstream-wasm-rust-sdk/examples at main · machinefi/w3bstream-wasm-rust-sdk · GitHub](https://github.com/machinefi/w3bstream-wasm-rust-sdk/tree/main/examples)
