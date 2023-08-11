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

use crate::olm::OlmSession;
use crate::omemo::GroupSession;

// creates a group session that allocated on the heap
#[no_mangle]
pub unsafe extern "C" fn self_omemo_create_group_session() -> *mut GroupSession {
    GroupSession::new()
}

// creates a group session that allocated on the heap
#[no_mangle]
pub unsafe extern "C" fn self_omemo_set_identity(gs: *mut GroupSession, id: *const c_char) {
    (*gs).set_identity(id);
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
    (*gs).add_participant(id, s);
}

// get the size of an encrypted message from the plaintext size
#[no_mangle]
pub unsafe extern "C" fn self_omemo_encrypted_size(
    gs: *mut GroupSession,
    pt_len: size_t,
) -> size_t {
    (*gs).encrypted_size(pt_len)
}

// get the size of a decrypted message from the ciphertext
#[no_mangle]
pub unsafe extern "C" fn self_omemo_decrypted_size(
    gs: *mut GroupSession,
    ct: *const u8,
    ct_len: size_t,
) -> size_t {
    (*gs).decrypted_size(ct, ct_len)
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
    (*gs).encrypt(pt, pt_len, ct, ct_len)
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
    (*gs).decrypt(id, pt, pt_len, ct, ct_len)
}
