use libc::{c_void};
use olm_sys::*;

pub struct OlmAccount {
    ptr: *mut olm_sys::OlmAccount,
}

pub struct OlmSession {
    ptr: *mut olm_sys::OlmSession,
}

impl OlmSession {
    pub unsafe fn ptr(&self) -> *mut olm_sys::OlmSession {
        self.ptr
    }
}

// wrap olm functions
#[no_mangle]
pub unsafe extern "C" fn self_olm_account(memory: *mut ::std::os::raw::c_void) -> *mut OlmAccount {
    Box::into_raw(Box::new(OlmAccount{ptr: olm_account(memory)}))
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_size() -> u64 {
    olm_account_size()
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_create_account_random_length(account: *mut OlmAccount) -> u64 {
    olm_create_account_random_length((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_create_account(account: *mut OlmAccount, random: *mut ::std::os::raw::c_void, random_length: u64) -> u64 {
    olm_create_account((*account).ptr, random, random_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_import_account(account: *mut OlmAccount, ed25519_secret_key: *mut ::std::os::raw::c_void, ed25519_public_key: *mut ::std::os::raw::c_void, curve25519_secret_key: *mut ::std::os::raw::c_void, curve25519_public_key: *mut ::std::os::raw::c_void) -> u64 {
    olm_import_account((*account).ptr, ed25519_secret_key, ed25519_public_key, curve25519_secret_key, curve25519_public_key)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_unpickle_account(account: *mut OlmAccount, key: *const c_void, key_length: u64, pickled: *mut c_void, pickled_length: u64) -> u64 {
    olm_unpickle_account((*account).ptr, key, key_length, pickled, pickled_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_pickle_account(account: *mut OlmAccount, key: *const c_void, key_length: u64, pickled: *mut c_void, pickled_length: u64) -> u64 {
    olm_pickle_account((*account).ptr, key, key_length, pickled, pickled_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_pickle_account_length(account: *const OlmAccount) -> u64 {
    olm_pickle_account_length((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_signature_length(account: *const OlmAccount) -> u64 {
    olm_account_signature_length((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_sign(account: *mut OlmAccount, message: *const ::std::os::raw::c_void, message_length: u64, signature: *mut ::std::os::raw::c_void, signature_length: u64) -> u64 {
    olm_account_sign((*account).ptr, message, message_length, signature, signature_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_max_number_of_one_time_keys(account: *mut OlmAccount) -> u64 {
    olm_account_max_number_of_one_time_keys((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_mark_keys_as_published(account: *mut OlmAccount) -> u64 {
    olm_account_mark_keys_as_published((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_generate_one_time_keys_random_length(account: *mut OlmAccount, number_of_keys: u64) -> u64 {
    olm_account_generate_one_time_keys_random_length((*account).ptr, number_of_keys)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_generate_one_time_keys(account: *mut OlmAccount, number_of_keys: u64, random: *mut c_void, random_length: u64) -> u64 {
    olm_account_generate_one_time_keys((*account).ptr, number_of_keys, random, random_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_one_time_keys_length(account: *const OlmAccount) -> u64 {
    olm_account_one_time_keys_length((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_one_time_keys(account: *mut OlmAccount, one_time_keys: *mut c_void, one_time_keys_length: u64) -> u64 {
    olm_account_one_time_keys((*account).ptr, one_time_keys, one_time_keys_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_remove_one_time_keys(account: *mut OlmAccount, session: *mut OlmSession) -> u64 {
    olm_remove_one_time_keys((*account).ptr, (*session).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_identity_keys_lengths(account: *mut OlmAccount) -> u64 {
    olm_account_identity_keys_length((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_identity_keys(account: *mut OlmAccount, identity_keys: *mut c_void, identity_key_length: u64) -> u64 {
    olm_account_identity_keys((*account).ptr, identity_keys, identity_key_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_last_error(account: *const OlmAccount) -> *const i8 {
    olm_account_last_error((*account).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_account_destroy(account: *mut OlmAccount)  {
    let _ = Box::from_raw(account);
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_session(memory: *mut c_void) -> *mut OlmSession {
    Box::into_raw(Box::new(OlmSession{ptr: olm_session(memory) }))
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_session_size() -> u64 {
    olm_session_size()
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_create_outbound_session_random_length(session: *const OlmSession) -> u64 {
    olm_create_outbound_session_random_length((*session).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_create_outbound_session(session: *mut OlmSession, account: *const OlmAccount, their_identity_key: *const c_void, their_identity_key_length: u64, their_one_time_key: *const c_void, their_one_time_key_length: u64, random: *mut c_void, random_length: u64) -> u64 {
    olm_create_outbound_session((*session).ptr, (*account).ptr, their_identity_key, their_identity_key_length, their_one_time_key, their_one_time_key_length, random, random_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_create_inbound_session(session: *mut OlmSession, account: *mut OlmAccount, one_time_key_message: *mut c_void, message_length: u64) -> u64 {
    olm_create_inbound_session((*session).ptr, (*account).ptr, one_time_key_message, message_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_create_inbound_session_from(session: *mut OlmSession, account: *mut OlmAccount, their_identity_key: *const c_void, their_identity_key_length: u64, one_time_key_message: *mut c_void, message_length: u64) -> u64 {
    olm_create_inbound_session_from((*session).ptr, (*account).ptr, their_identity_key, their_identity_key_length, one_time_key_message, message_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_unpickle_session(session: *mut OlmSession, key: *const c_void, key_length: u64, pickled: *mut c_void, pickled_length: u64) -> u64 {
    olm_unpickle_session((*session).ptr, key, key_length, pickled, pickled_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_pickle_session(session: *mut OlmSession, key: *const c_void, key_length: u64, pickled: *mut c_void, pickled_length: u64) -> u64 {
    olm_pickle_session((*session).ptr, key, key_length, pickled, pickled_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_pickle_session_length(session: *const OlmSession) -> u64 {
    olm_pickle_session_length((*session).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_encrypt_message_type(session: *const OlmSession) -> u64 {
    olm_encrypt_message_type((*session).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_matches_inbound_session(session: *mut OlmSession, one_time_key_message: *mut c_void, message_length: u64) -> u64 {
    olm_matches_inbound_session((*session).ptr, one_time_key_message, message_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_matches_inbound_session_from(session: *mut OlmSession, their_identity_key: *const c_void, their_identity_key_length: u64, one_time_key_message: *mut c_void, message_length: u64) -> u64 {
    olm_matches_inbound_session_from((*session).ptr, their_identity_key, their_identity_key_length, one_time_key_message, message_length)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_session_last_error(session: *mut OlmSession) -> *const i8 {
    olm_session_last_error((*session).ptr)
}

#[no_mangle]
pub unsafe extern "C" fn self_olm_session_destroy(session: *mut OlmSession)  {
    let _ = Box::from_raw(session);
}