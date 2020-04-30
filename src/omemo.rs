extern crate libc;
extern crate base64;

include!(concat!(env!("OUT_DIR"), "/olm.rs"));

use std::slice;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use std::ptr;
use base64::{encode_config, decode_config};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;
use crate::message::{Message, GroupMessage, decode_group_message};

pub struct GroupSession{
    id: String,
    participants: Vec<Participant>,
}

struct Participant {
    id: String,
    session: *mut OlmSession,
}

impl GroupSession {
    pub fn new(id: *mut i8) -> *mut GroupSession {
        let idstr: CString;

        unsafe {
            idstr = CString::from_raw(id);
        }

        let gs = GroupSession{
            id: idstr.into_string().unwrap(),
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

    pub fn encrypted_size(&mut self, pt_len: size_t) -> size_t {
        let pt_sz: usize;

        unsafe {
            // include 16 byte validation tag
            pt_sz = sodium_base64_encoded_len(pt_len+24, sodium_base64_VARIANT_ORIGINAL_NO_PADDING as i32) as usize;
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

    pub fn decrypted_size(&mut self, ct: *const u8, ct_len: size_t) -> size_t {
        let gm = decode_group_message(ct, ct_len as usize);
        if gm.is_err() {
            return 0;
        }

        let pt_len = gm.unwrap().ciphertext.len() - (16 as usize);

        return pt_len as size_t
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

            let mut rand_buf: Vec<u8> = vec![0; rand_sz as usize];

            if rand_sz > 0 {
                unsafe {
                    randombytes_buf(rand_buf.as_mut_ptr() as *mut libc::c_void, rand_sz);
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
            let mut ct_buf: Vec<u8> = vec![0; ct_sz as usize];

            unsafe {
                ct_sz = olm_encrypt(
                    p.session,
                    grp_pt.as_mut_ptr() as *mut libc::c_void,
                    grp_pt.len() as u64,
                    rand_buf.as_mut_ptr() as *mut libc::c_void,
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
            let cts = String::from_utf8(ct_buf); //[0..ct_sz as usize].to_vec());
            if cts.is_err() {
                return 0;
            }

            let ct = cts.unwrap();

            // add encrypted key + nonce to group message
            gm.add_recipient(p.id.clone(), Message::new(mtype as i64, ct));
        }

        // copy encoded json to ciphertext buffer
        let result = gm.encode_to_buffer(ct, ct_len);
        if result.is_err() {
            return 0;
        }

        return result.unwrap() as size_t;
    }

    pub fn decrypt(&mut self, id: *mut i8, pt: *mut u8, pt_len: size_t, ct: *const u8, ct_len: size_t) -> size_t {
        let idstr: CString;

        unsafe {
            idstr = CString::from_raw(id);
        }

        let pidstr = idstr.into_string();
        if pidstr.is_err() {
            return 0;
        };

        let pid = pidstr.unwrap();

        // get the index of the senders session
        let sp = self.participants.iter().position(|p| p.id == pid);
        if sp.is_none() {
            return 0;
        }

        let spi = sp.unwrap();

        let s = self.participants[spi].session;

        // decode the group message
        let dgm = decode_group_message(ct, ct_len as usize);
        if dgm.is_err() {
            return 0;
        }

        let gm = dgm.unwrap();

        // get the encrypted ciphertext key from the header
        let mh = gm.recipients.get(&self.id);
        if mh.is_none() {
            return 0;
        }

        let header = mh.unwrap();

        // convert the ciphetext string to a byte array and create a second copy,
        // as olm_decrypt_max_plaintext_length mutates the buffer
        let mut ctk_buf = String::from(header.ciphertext.clone()).into_bytes();
        let mut ctk_buf_cpy = String::from(header.ciphertext.clone()).into_bytes();

        let ptk_sz: size_t;

        unsafe {
            // get the size of the decrypted keys plaintext
            ptk_sz = olm_decrypt_max_plaintext_length(
                s,
                header.mtype as size_t,
                ctk_buf_cpy.as_mut_ptr() as *mut libc::c_void,
                ctk_buf_cpy.len() as size_t,
            );
        }

        let mut last_err = session_error(s);
        if last_err.is_some() {
            return 0;
        }

        let mut ptk_buf: Vec<u8> = vec![0; ptk_sz as usize];

        unsafe {
            olm_decrypt(
                s,
                header.mtype as size_t,
                ctk_buf.as_mut_ptr() as *mut libc::c_void,
                ctk_buf.len() as size_t,
                ptk_buf.as_mut_ptr() as *mut libc::c_void,
                ptk_sz,
            );
        }

        last_err = session_error(s);
        if last_err.is_some() {
            return 0;
        }

        // get key and nonce from header plaintext
        let pt_key = xchacha20poly1305_ietf::Key::from_slice(&ptk_buf[0..32]);
        if pt_key.is_none() {
            return 0;
        }

        let key = pt_key.unwrap();

        let pt_nonce = xchacha20poly1305_ietf::Nonce::from_slice(&ptk_buf[32..56]);
        if pt_nonce.is_none() {
            return 0;
        }

        let nonce = pt_nonce.unwrap();

        // decode the group messages ciphertext from base64
        let dec = decode_config(gm.ciphertext, base64::STANDARD_NO_PAD);
        if dec.is_err() {
            return 0;
        }

        let dec_ct = dec.unwrap();

        let dec_pt_result = xchacha20poly1305_ietf::open(&dec_ct[..], None, &nonce, &key);
        if dec_pt_result.is_err() {
            return 0;
        }

        let mut dec_pt = dec_pt_result.unwrap();

        // TODO : check pt buffer is big enough
        unsafe {
            ptr::copy(dec_pt.as_mut_ptr(), pt, pt_len as usize);
        }

        return dec_pt.len() as size_t;
    }
}

#[no_mangle]
pub unsafe extern "C" fn omemo_create_group_session(id: *const c_char) -> *mut GroupSession {
    return GroupSession::new(id as *mut i8);
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
pub unsafe extern "C" fn omemo_encrypted_size(gs: *mut GroupSession, pt_len: size_t) -> size_t {
    return (*gs).encrypted_size(pt_len);
}

#[no_mangle]
pub unsafe extern "C" fn omemo_decrypted_size(gs: *mut GroupSession, ct: *const u8, ct_len: size_t) -> size_t {
    return (*gs).decrypted_size(ct, ct_len);
}

#[no_mangle]
pub unsafe extern "C" fn omemo_encrypt(gs: *mut GroupSession, pt: *const u8, pt_len: size_t, ct: *mut u8, ct_len: size_t) -> size_t {
    return (*gs).encrypt(pt, pt_len, ct, ct_len)
}

#[no_mangle]
pub unsafe extern "C" fn omemo_decrypt(gs: *mut GroupSession, id: *const c_char, pt: *mut u8, pt_len: size_t, ct: *const u8, ct_len: size_t) -> size_t {
    return (*gs).decrypt(id as *mut i8, pt, pt_len, ct, ct_len)
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
        println!("OLM {:?}", err_str);
    }

    if err_str != "SUCCESS" {
        return Some(err_str);
    }

    return None;
}
