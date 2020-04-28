extern crate libc;
extern crate base64;

include!(concat!(env!("OUT_DIR"), "/olm.rs"));

use std::ffi::IntoStringError;
use std::slice;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use base64::{encode_config};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;
use crate::message::{Message, GroupMessage};

pub struct GroupSession{
    participants: Vec<Participant>,
}

struct Participant {
    id: String,
    session: *mut OlmSession,
}

impl GroupSession {
    pub fn new() -> *mut GroupSession {
        let gs = GroupSession{
            participants: Vec::new(),
        };

        return Box::into_raw(Box::new(gs))
    }

    pub fn add_participant(&mut self, id: *mut i8, s: *mut OlmSession) -> size_t {
        let idstr: CString;

        unsafe {
            idstr = CString::from_raw(id);
        }

        let pid = idstr.into_string();

        if pid.is_err() {
            return 1;
        };

        self.participants.push(Participant{
            id: String::from(pid.unwrap()),
            session: s,
        });

        return 0;
    }

    pub fn encrypted_size(&mut self, ptlen: size_t) -> size_t {
        let pt_sz: usize;

        unsafe {
            // include 16 byte validation tag
            pt_sz = sodium_base64_encoded_len(ptlen+24, sodium_base64_VARIANT_ORIGINAL_NO_PADDING as i32) as usize;
        }

        let pt = String::from_utf8(vec![b'X'; pt_sz]);
        if pt.is_err() {
            return 0;
        }

        let mut gm = GroupMessage::new(pt.unwrap());

        for p in &self.participants {
            let enc_sz: u64;

            unsafe {
                enc_sz = olm_encrypt_message_length(
                    p.session,
                    32 + 24,
                );
            }

            // create mock recipient key
            let ky = String::from_utf8(vec![b'X'; enc_sz as usize]);
            if ky.is_err() {
                return 0;
            }

            let key = ky.unwrap();

            gm.add_recipient(p.id.clone(), Message::new(0, key.clone()));
        }

        let res = gm.encode();

        if res.is_err() {
            return 0;
        }

        let alen = res.unwrap().len();

        return alen as size_t;
    }

    pub fn encrypt(&mut self, pt: *const u8, pt_len: size_t, ct: *mut u8, ct_len: size_t) -> size_t {
        assert!(!pt.is_null(), "plaintext buffer must not be null");
        assert!(!ct.is_null(), "ciphertext buffer must not be null");
        //assert!(self.encrypted_size(pt_len) > ct_len, "ciphertext buffer is not big enough");

        if sodiumoxide::init().is_err() {
            return 0;
        }

        // convert the c plaintext to a rust slice
        let pt_buf: &[u8];

        unsafe {
            pt_buf = slice::from_raw_parts(pt, pt_len as usize);
        }

        // create group message key
        let k = xchacha20poly1305_ietf::gen_key();
        let n = xchacha20poly1305_ietf::gen_nonce();

        let ctb = xchacha20poly1305_ietf::seal(pt_buf, None, &n, &k);

        // encode the ciphertext to base64
        let enc_ct = encode_config(ctb, base64::STANDARD_NO_PAD);

        let mut gm = GroupMessage::new(enc_ct);

        // join the key and nonce together
        let mut grp_pt = concat_u8(k.as_ref(), n.as_ref());

        // encrypt group message key with participants olm sessions
        for p in &self.participants {
            // get the message type and size of random needed to encrypt
            let mtype: u64;
            let rand_sz: u64;

            unsafe {
                mtype = olm_encrypt_message_type(p.session);
                rand_sz = olm_encrypt_random_length(p.session);
            }

            let mut rand_buf = Vec::with_capacity(rand_sz as usize);

            if rand_sz > 0 {
                unsafe {
                    randombytes_buf(rand_buf.as_mut_ptr(), rand_sz);
                }
            }

            let mut ct_sz: u64;

            unsafe {
                ct_sz = olm_encrypt_message_length(
                    p.session,
                    32 + 24,
                );

                let last_err = session_error(p.session);

                if last_err.is_some() {
                    println!("Error: {:?}", last_err.unwrap());
                    return 0;
                }
            }

            // allocate buffer for the ciphertext and encrypt the key + nonce
            let mut ct_buf: Vec<u8> = Vec::with_capacity(ct_sz as usize);

            unsafe {
                ct_sz = olm_encrypt(
                    p.session,
                    grp_pt.as_mut_ptr() as *mut libc::c_void,
                    grp_pt.len() as u64,
                    rand_buf.as_mut_ptr(),
                    rand_sz,
                    ct_buf.as_mut_ptr() as *mut libc::c_void,
                    ct_sz,
                );

                let last_err = session_error(p.session);

                if last_err.is_some() {
                    println!("Error: {:?}", last_err.unwrap());
                    return 0;
                }
            }

            // trim unused space
            let ct = String::from_utf8(ct_buf);//[0..ct_sz as usize].to_vec());
            if ct.is_err() {
                return 0;
            }

            // add encrypted key + nonce to group message
            gm.add_recipient(p.id.clone(), Message::new(mtype as i64, ct.unwrap()));
        }

        // copy encoded json to ciphertext buffer
        let result = gm.encode_to_buffer(ct, ct_len);
        if result.is_err() {
            return 0;
        }

        return result.unwrap() as size_t;
    }
}

#[no_mangle]
pub unsafe extern "C" fn omemo_create_group_session() -> *mut GroupSession {
    return GroupSession::new();
}

#[no_mangle]
pub unsafe extern "C" fn omemo_destroy_group_session(gs: *mut GroupSession) {
    // consume the box to deallocate the session
    Box::from_raw(gs);
}

#[no_mangle]
pub unsafe extern "C" fn omemo_add_group_participant(gs: *mut GroupSession, id: *const c_char, s: *mut OlmSession) {
    (*gs).add_participant(id as *mut i8 , s);
}

#[no_mangle]
pub unsafe extern "C" fn omemo_encrypted_size(gs: *mut GroupSession, sz: size_t) -> size_t {
    return (*gs).encrypted_size(sz);
}

#[no_mangle]
pub unsafe extern "C" fn omemo_encrypt(gs: *mut GroupSession, pt: *const u8, pt_len: size_t, ct: *mut u8, ct_len: size_t) -> size_t {
    return (*gs).encrypt(pt, pt_len, ct, ct_len)
}

fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

fn session_error(s: *mut OlmSession) -> Option<String> {
    let err_str: String;

    unsafe {
        let err = olm_session_last_error(s);
        let err_str_cnv = CStr::from_ptr(err).to_str();
        err_str = String::from(err_str_cnv.unwrap());
    }

    if err_str != "SUCCESS" {
        return Some(err_str);
    }

    return None;
}
