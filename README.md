# This is a Rust library to interface with the [eHSM](https://ellipticsecure.com/products/ehsm_overview.html) and [MIRkey](https://ellipticsecure.com/products/mirkey_overview.html) Hardware Security Modules

[![Latest version](https://img.shields.io/crates/v/ehsm.svg)](https://crates.io/crates/ehsm)
[![Documentation](https://docs.rs/ehsm/badge.svg)](https://docs.rs/ehsm)
![License](https://img.shields.io/crates/l/pkcs11.svg)

# Example usage

```rust
    ...
    let lib_name = ehsm_library_name();
    let ehsm = EHSMContext::new(lib_name.as_path()).expect("Failed to load ehsm library functions");
    let session = get_logged_in_session(&ctx,SU_PIN, 0,None, None).expect("Failed to get session");
    let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    if ehsm.has_bitcoin_key(session, &mut oh).unwrap() {
        println!("already has btc key.");
    } else {
        ehsm.import_bitcoin_key(session,
                            &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap())
        .expect("Failed to import key");
    }

    // empty index vector is the root key or "m"
    // for "m/0", just add 0 to indexes, i.e. indexes.push(0) etc. to build the BIP32 path
    let mut indexes: Vec<u32> = Vec::new();
    let net: u32 = 0x0488B21Eu32;
    let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc xpub");
    ...
    // sign a 32 byte transaction hash
    let sig = ehsm.sign_bitcoin_hash(session,&vec![0;32],&indexes).expect("Failed to sign hash");

```
Also see the integration tests here:
   * [tests.rs](https://github.com/ellipticSecure/ehsm-rust/tests/tests.rs)
