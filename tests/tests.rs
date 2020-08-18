// Copyright (c) 2020 ellipticSecure
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate serial_test_derive;

use pkcs11::*;
use pkcs11::types::*;
use ehsm::*;

const SU_PIN: &str = "testsu";

#[test]
#[serial]
fn test_btc_vect1() {

    let lib_name = ehsm_library_name();
    let ehsm = EHSMContext::new(lib_name.as_path()).expect("Failed to load ehsm library functions");

    let mut ctx = Ctx::new(lib_name).expect("Failed to load ehsm pkcs11 library");

    let _r = ctx.finalize();

    let args = CK_C_INITIALIZE_ARGS::new();

    ctx.initialize(Option::from(args)).expect("Failed to initialize PKCS11");

    let session = get_logged_in_session(&ctx,SU_PIN, 0,None, None).expect("Failed to get session");

    let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    if ehsm.has_bitcoin_key(session, &mut oh).unwrap() {
        println!("already has btc key - destroying.");
        ctx.destroy_object(session, oh).expect("Failed to destroy key");
    }
    ehsm.import_bitcoin_key(session,
                            &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap())
        .expect("Failed to import key");

    // perform BIP32 tests from test vectors defined in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

    let mut indexes: Vec<u32> = Vec::new();
    let net: u32 = 0x0488B21Eu32;
    let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc pub");
    assert_eq!("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",xpub);

    indexes.push(0x80000000u32);
    let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc pub");
    assert_eq!("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",xpub);

    indexes.push(1);
    let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc pub");
    assert_eq!("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",xpub);

    indexes.push(0x80000002u32);
    let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc pub");
    assert_eq!("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",xpub);

    indexes.push(2);
    let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc pub");
    assert_eq!("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",xpub);

    indexes.push(1000000000);
    let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc pub");
    assert_eq!("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",xpub);
}

#[test]
#[serial]
fn test_btc_sign() {
    let lib_name = ehsm_library_name();
    let ehsm = EHSMContext::new(lib_name.as_path()).expect("Failed to load ehsm library functions");

    let mut ctx = Ctx::new(lib_name).expect("Failed to load ehsm pkcs11 library");

    let _r = ctx.finalize();

    let args = CK_C_INITIALIZE_ARGS::new();
    ctx.initialize(Option::from(args)).expect("Failed to initialize PKCS11");

    let session = get_logged_in_session(&ctx, SU_PIN,0,None,None).expect("Failed to get session");

    let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    if ehsm.has_bitcoin_key(session, &mut oh).unwrap() {
        println!("already has btc key - destroying.");
        ctx.destroy_object(session, oh).expect("Failed to destroy key");
    }
    ehsm.import_bitcoin_key(session,
                            &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap())
        .expect("Failed to import key");

    let sig = ehsm.sign_bitcoin_hash(session,&vec![0;32],&Vec::new()).expect("Failed to sign hash");
    assert_eq!("3045022100faf92a52783a193c7000ccb665aedf7d1a8981d9de907c057013749e67f4451e02207ee2fd0e13cbf2c6fa0a73b29f42c7cbb124b8874c4b39c9b11dd3c8942de13d",
               hex::encode(sig));
}
