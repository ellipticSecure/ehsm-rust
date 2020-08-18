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

//! # ehsm
//!
//! `ehsm` is a rust integration library to use the non-PKCS11 functions from the
//! ehsm shared library. Use this crate in conjunction with the [`pkcs11`][] crate.
//!
//! [`pkcs11`]: https://crates.io/crates/pkcs11
//!
#![allow(non_camel_case_types, non_snake_case, clippy::unreadable_literal)]

extern crate pkcs11;
extern crate libloading;

use std::path::Path;
use std::path::PathBuf;
use std::env;
use pkcs11::types::*;
use pkcs11::errors::Error;
use ::libloading::{Symbol};

/// A utility function to retrieve the library name from the EHSM_LIBRARY environment variable or default path
pub fn ehsm_library_name() -> PathBuf {
    let mut default = "/usr/local/lib/libehsm.so";
    if cfg!(target_os = "macos") {
        default = "/usr/local/lib/libehsm.dylib";
    } else if cfg!(target_os = "windows") {
        default = "ehsm.dll";
    }

    let default_path =
        option_env!("EHSM_LIBRARY").unwrap_or(default);
    let path = env::var_os("EHSM_LIBRARY").unwrap_or_else(|| default_path.into());
    let path_buf = PathBuf::from(path);

    if !path_buf.exists() {
        panic!(
            "Could not find the eHSM library at `{}`. Set the `EHSM_LIBRARY` environment variable to \
       its location.",
            path_buf.display());
    }

    path_buf
}

/// A utility function to open a session and log-in
pub fn get_logged_in_session(ctx: &pkcs11::Ctx, pin: &str, slot_idx: usize, user_type: Option<CK_USER_TYPE>, flags: Option<CK_FLAGS>)
                             -> Result<CK_SESSION_HANDLE, Error> {
    let slot_list = ctx.get_slot_list(true)
        .expect("Failed to get slots");
    if slot_list.len() <= slot_idx {
        // No slots found
        return Err(Error::Pkcs11(CKR_SLOT_ID_INVALID));
    }
    let flags = match flags {
        Some(flags) => flags,
        None => CKF_SERIAL_SESSION | CKF_RW_SESSION,
    };
    let session = ctx.open_session(slot_list[slot_idx],
                                   flags,
                                   None, None)?;

    let user_type = match user_type {
        Some(user) => user,
        None => CKU_USER,
    };

    let r = ctx.login(session, user_type, Option::from(pin));
    if r.is_err() {
        let _ = ctx.close_session(session);
        return Err(r.unwrap_err());
    }

    Ok(session)
}

pub const BTC_KEY_NOT_FOUND: CK_RV = CKR_VENDOR_DEFINED + 1;

// uint32_t u32HasBitcoinKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *handle)
pub type u32HasBitcoinKey = extern "C" fn(hSession: CK_SESSION_HANDLE, handle: CK_OBJECT_HANDLE_PTR) -> CK_RV;
// uint32_t u32ImportBitcoinKey(CK_SESSION_HANDLE session, const uint8_t* seedIn, size_t seedLen)
pub type u32ImportBitcoinKey = extern "C" fn(hSession: CK_SESSION_HANDLE, seedIn: *const u8, seedLen: usize) -> CK_RV;

// uint32_t u32GetBitcoinPub(CK_SESSION_HANDLE session, uint32_t* indexes, size_t indexCnt, uint8_t *out, size_t *outLen)
pub type u32GetBitcoinPub = extern "C" fn(hSession: CK_SESSION_HANDLE, indexes: *mut u32,
                                          indexCnt: usize, out: *mut u8, outLen: *mut usize) -> CK_RV;

// uint32_t u32SignBitcoinHash(CK_SESSION_HANDLE session, const uint8_t* hash, size_t hashLen,
//                                uint32_t* indexes, size_t indexCnt, uint8_t* sig, size_t *sigLenInOut)
pub type u32SignBitcoinHash = extern "C" fn(hSession: CK_SESSION_HANDLE, hash: *const u8, hashLen: usize,
                                            indexes: *mut u32, indexCnt: usize, sig: *mut u8, sigLenInOut: *mut usize) -> CK_RV;

pub struct EHSMContext {
    lib: libloading::Library,
    u32HasBitcoinKey: u32HasBitcoinKey,
    u32ImportBitcoinKey: u32ImportBitcoinKey,
    u32GetBitcoinPub: u32GetBitcoinPub,
    u32SignBitcoinHash: u32SignBitcoinHash,
}

impl EHSMContext {
    /// Creates a new EHSMContext from the shared library name
    ///
    /// # Examples
    /// ```
    ///     use ehsm::*;
    ///     let lib_name = ehsm_library_name();
    ///     let ehsm = EHSMContext::new(lib_name.as_path()).expect("Failed to load ehsm library functions");
    /// ```
    pub fn new<P>(filename: P) -> Result<EHSMContext, Error>
        where
            P: AsRef<Path>,
    {
        unsafe {
            let lib = libloading::Library::new(filename.as_ref())?;
            let func: Symbol<u32HasBitcoinKey> = lib.get(b"u32HasBitcoinKey\0")?;
            let u32HasBitcoinKey = func.into_raw();
            let func: Symbol<u32ImportBitcoinKey> = lib.get(b"u32ImportBitcoinKey\0")?;
            let u32ImportBitcoinKey = func.into_raw();
            let func: Symbol<u32GetBitcoinPub> = lib.get(b"u32GetBitcoinPub\0")?;
            let u32GetBitcoinPub = func.into_raw();
            let func: Symbol<u32SignBitcoinHash> = lib.get(b"u32SignBitcoinHash\0")?;
            let u32SignBitcoinHash = func.into_raw();
            Ok(
                EHSMContext {
                    lib,
                    u32HasBitcoinKey: *u32HasBitcoinKey,
                    u32ImportBitcoinKey: *u32ImportBitcoinKey,
                    u32GetBitcoinPub: *u32GetBitcoinPub,
                    u32SignBitcoinHash: *u32SignBitcoinHash,
                })
        }
    }

    /// Returns true if the device has a bitcoin key object. If it does have a key, the object handle is returned
    /// in handle.
    pub fn has_bitcoin_key(
        &self,
        session: CK_SESSION_HANDLE,
        handle: CK_OBJECT_HANDLE_PTR) -> Result<bool, Error> {
        let r = (self.u32HasBitcoinKey)(session, handle);
        if r == CKR_OK {
            return Ok(true);
        }
        if r == BTC_KEY_NOT_FOUND {
            return Ok(false);
        }
        Err(Error::Pkcs11(r))
    }

    /// Import a bitcoin key from the provided binary seed
    ///
    pub fn import_bitcoin_key(
        &self,
        session: CK_SESSION_HANDLE,
        seed: &Vec<u8>) -> Result<(), Error> {
        match (self.u32ImportBitcoinKey)(session, seed.as_ptr(), seed.len())
        {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    /// Sign the provided hash with the private key at the specified BIP32 path.
    /// The path is defined by the indexes provided.
    /// # Examples
    /// ```
    ///     use ehsm::*;
    ///     // empty index vector is the root key or "m"
    ///     // for "m/0", just add 0 to indexes, i.e. indexes.push(0) etc. to build the BIP32 path
    ///     let mut indexes: Vec<u32> = Vec::new();
    ///     // let sig = ehsm.sign_bitcoin_hash(session,&vec![0;32],&indexes).expect("Failed to sign hash");
    /// ```
    pub fn sign_bitcoin_hash(
        &self,
        session: CK_SESSION_HANDLE,
        hash: &Vec<u8>,
        indexes: &Vec<u32>) -> Result<Vec<u8>, Error> {
        let mut idx_clone = indexes.clone();
        let mut out: [u8; 128] = [0; 128];
        let mut out_size: usize = out.len();

        match (self.u32SignBitcoinHash)(session, hash.as_ptr(), hash.len(), idx_clone.as_mut_ptr(),
                                        indexes.len(), out.as_mut_ptr(), &mut out_size)
        {
            CKR_OK => Ok((&out[0..out_size]).to_vec()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    /// Get the BTC base58 encoded public key at the specified BIP32 path. The path is defined by the indexes provided.
    /// # Examples
    /// ```
    ///     use ehsm::*;
    ///     // empty index vector is the root key or "m"
    ///     // for "m/0", just add 0 to indexes, i.e. indexes.push(0) etc. to build the BIP32 path
    ///     let mut indexes: Vec<u32> = Vec::new();
    ///     // main net
    ///     let net: u32 = 0x0488B21Eu32;
    ///     // let xpub = ehsm.get_bitcoin_pub(session, &indexes, net).expect("Failed to get btc pub");
    /// ```
    pub fn get_bitcoin_pub(&self,
                           session: CK_SESSION_HANDLE,
                           indexes: &Vec<u32>, net: u32) -> Result<String, Error> {
        let mut out: [u8; 128] = [0; 128];
        let mut out_size: usize = out.len() - 4;
        out[0..4].copy_from_slice(&net.to_be_bytes());
        let outp = out[4..].as_mut_ptr();
        let mut idx_clone = indexes.clone();
        let err = (self.u32GetBitcoinPub)(session, idx_clone.as_mut_ptr(), indexes.len(), outp, &mut out_size);
        if err != CKR_OK {
            return Err(Error::Pkcs11(err));
        }

        Ok(bs58::encode(&out[0..out_size + 4])
            .with_alphabet(bs58::alphabet::BITCOIN).with_check().into_string())
    }
}
