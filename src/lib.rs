// Copyright 2020 Self Group Ltd. All Rights Reserved.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::missing_safety_doc)]

// include all of the other modules in the library
pub mod message;
pub mod olm;
pub mod omemo;
pub mod sodium;

use libc::{c_char, size_t};
use std::ffi::CStr;

use crate::olm::OlmSession;
use crate::omemo::GroupSession;

// creates a group session that allocated on the heap
#[no_mangle]
pub unsafe extern "C" fn self_omemo_create_group_session() -> *mut GroupSession {
    Box::into_raw(Box::new(GroupSession::new()))
}

// creates a group session that allocated on the heap
#[no_mangle]
pub unsafe extern "C" fn self_omemo_set_identity(gs: *mut GroupSession, id: *const c_char) {
    let idstr = CStr::from_ptr(id).to_str();

    if idstr.is_err() {
        println!("error: {}", idstr.unwrap_err());
    };

    (*gs).set_identity(idstr.unwrap().to_string());
}

// destroy a group session by consuming the box
#[no_mangle]
pub unsafe extern "C" fn self_omemo_destroy_group_session(gs: *mut GroupSession) {
    // consume the box to deallocate the session
    _ = Box::from_raw(gs);
}

// add a participant to a group session
#[no_mangle]
pub unsafe extern "C" fn self_omemo_add_group_participant(
    gs: *mut GroupSession,
    id: *const c_char,
    s: *mut OlmSession,
) {
    let idstr = CStr::from_ptr(id).to_str();

    if idstr.is_err() {
        println!("error: {}", idstr.unwrap_err());
    };

    (*gs).add_participant(idstr.unwrap().to_string(), s);
}

// get the size of an encrypted message from the plaintext size
#[no_mangle]
pub unsafe extern "C" fn self_omemo_encrypted_size(
    gs: *mut GroupSession,
    pt_len: size_t,
) -> size_t {
    (*gs).encrypted_size(pt_len).expect("this shouldn't fail")
}

// get the size of a decrypted message from the ciphertext
#[no_mangle]
pub unsafe extern "C" fn self_omemo_decrypted_size(
    gs: *mut GroupSession,
    ct: *const u8,
    ct_len: size_t,
) -> size_t {
    let ciphertext = std::slice::from_raw_parts(ct, ct_len);
    (*gs).decrypted_size(ciphertext)
}

// encrypt a message for all participants in the group session
#[no_mangle]
pub unsafe extern "C" fn self_omemo_encrypt(
    gs: *mut GroupSession,
    pt: *const u8,
    pt_len: size_t,
    ct: *mut u8,
    ct_len: size_t,
) -> size_t {
    assert!(!pt.is_null(), "plaintext buffer must not be null");
    assert!(!ct.is_null(), "ciphertext buffer must not be null");

    let plaintext = std::slice::from_raw_parts(pt, pt_len);
    let ciphertext = std::slice::from_raw_parts_mut(ct, ct_len);

    match (*gs).encrypt(plaintext, ciphertext) {
        Ok(len) => len,
        Err(_) => 0,
    }
}

// decrypt a message from one of the recipients in the group session
#[no_mangle]
pub unsafe extern "C" fn self_omemo_decrypt(
    gs: *mut GroupSession,
    id: *const c_char,
    pt: *mut u8,
    pt_len: size_t,
    ct: *const u8,
    ct_len: size_t,
) -> size_t {
    assert!(!pt.is_null(), "plaintext buffer must not be null");
    assert!(!ct.is_null(), "ciphertext buffer must not be null");

    let plaintext = std::slice::from_raw_parts_mut(pt, pt_len);
    let ciphertext = std::slice::from_raw_parts(ct, ct_len);

    let identifier = match CStr::from_ptr(id).to_str() {
        Ok(identifier) => identifier,
        Err(_) => return 0,
    };

    match (*gs).decrypt(identifier, plaintext, ciphertext) {
        Ok(len) => len,
        Err(_) => 0,
    }
}
