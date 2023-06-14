// Copyright 2020 Self Group Ltd. All Rights Reserved.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use base64::{decode_config, encode_config};
use libc::{c_ulonglong, size_t};
use olm_sys::*;
use sodium_sys::*;

use crate::message::{decode_group_message, GroupMessage, Message};

// GroupSession holds all of the participants of a session,
// as well as the identity of the current user
// the id is used to determine which key to use
// when decrypting a message
pub struct GroupSession {
    id: Option<String>,
    participants: Vec<Participant>,
}

// Participant stores the id and related olm session of the recipients
// you want to encrypt a message for
struct Participant {
    id: String,
    session: *mut OlmSession,
}

impl GroupSession {
    // creates a new boxed group session allocated on the heap
    pub fn new() -> *mut GroupSession {
        let gs = GroupSession {
            id: None,
            participants: Vec::new(),
        };

        Box::into_raw(Box::new(gs))
    }

    pub unsafe fn set_identity(&mut self, id: *const c_char) {
        let idstr = CStr::from_ptr(id);
        let identity = idstr.to_str().unwrap().to_string();

        self.id = Some(identity);
    }

    // add a participcant and their session to the group session
    pub unsafe fn add_participant(
        &mut self,
        id: *const c_char,
        s: *mut crate::olm::OlmSession,
    ) -> size_t {
        let idstr = CStr::from_ptr(id).to_str();

        if idstr.is_err() {
            println!("error: {}", idstr.unwrap_err());
            return 1;
        };

        let pid = idstr.unwrap().to_string();

        self.participants.push(Participant {
            id: pid,
            session: (*s).ptr(),
        });

        0
    }

    // returns the size of an encrypted message based on the plaintext size
    pub fn encrypted_size(&mut self, pt_len: size_t) -> size_t {
        let pt_sz: usize;

        // generate a fake encoded message
        unsafe {
            // include 16 byte validation tag
            pt_sz = sodium_base64_encoded_len(
                pt_len + 24,
                sodium_base64_VARIANT_ORIGINAL_NO_PADDING as i32,
            );
        }

        let pt = String::from_utf8(vec![b'X'; pt_sz]);
        if pt.is_err() {
            println!("error: could not generate a placeholder ciphertext");
            return 0;
        }

        let mut gm = GroupMessage::new(pt.unwrap());

        // iterate over each participant and add a fake
        // encrypted key as its value
        for p in &self.participants {
            let enc_sz: size_t;

            // get the size of the ciphertext thats encrypted
            // by the olm session. the olm session
            // will be encrypting the key and nonce used
            // to generate the main messages ciphertext
            unsafe {
                enc_sz = olm_encrypt_message_length(p.session, 32 + 24) as size_t;
            }

            // create mock recipient key
            let ky = String::from_utf8(vec![b'X'; enc_sz]);
            if ky.is_err() {
                println!("error: could not generate a placeholder key");
                return 0;
            }

            let key = ky.unwrap();

            gm.add_recipient(p.id.clone(), Message::new(0, key.clone()));
        }

        // encode the fake message and return its size
        let res = gm.encode();

        if res.is_err() {
            println!("error: {:?}", res);
            return 0;
        }

        let alen = res.unwrap().len();

        alen as size_t
    }

    // returns the size of the paintext message based on the ciphertext
    pub unsafe fn decrypted_size(&mut self, ct: *const u8, ct_len: size_t) -> size_t {
        // decode the group message
        let gm = decode_group_message(ct, ct_len);
        if gm.is_err() {
            return 0;
        }

        // plaintext size is the messages ciphertext size minus the 16
        // bytes used by the cipher to authenticate the message
        let pt_len = gm.unwrap().ciphertext.len() - 16;

        pt_len as size_t
    }

    // encrypt a message
    pub unsafe fn encrypt(
        &mut self,
        pt: *const u8,
        pt_len: size_t,
        ct: *mut u8,
        ct_len: size_t,
    ) -> size_t {
        assert!(!pt.is_null(), "plaintext buffer must not be null");
        assert!(!ct.is_null(), "ciphertext buffer must not be null");
        //assert!(self.encrypted_size(pt_len) > ct_len, "ciphertext buffer is not big enough");

        // setup message ciphertext, key and nonce buffer
        let mut ctb: Vec<u8> = vec![0; pt_len + 16];
        let mut ctbl = ctb.len() as c_ulonglong;
        let mut kb: Vec<u8> = vec![0; 32];
        let mut nb: Vec<u8> = vec![0; 24];

        if sodium_init() == -1 {
            println!("error: sodium is not ready");
            return 0;
        }

        // create group message key
        crypto_aead_xchacha20poly1305_ietf_keygen(kb.as_mut_ptr());
        randombytes_buf(nb.as_mut_ptr() as *mut libc::c_void, 24);

        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ctb.as_mut_ptr(),
            &mut ctbl,
            pt,
            pt_len as u64,
            ptr::null(),
            0_u64,
            ptr::null_mut(),
            nb.as_mut_ptr(),
            kb.as_mut_ptr(),
        );

        ctb.set_len(ctbl as usize);

        // encode the ciphertext to base64
        let enc_ct = encode_config(ctb, base64::STANDARD_NO_PAD);

        let mut gm = GroupMessage::new(enc_ct);

        // join the key and nonce together
        let mut grp_pt = concat_u8(kb.as_ref(), nb.as_ref());

        // encrypt group message key with participants olm sessions
        for p in &self.participants {
            // get the message type and size of random needed to encrypt
            let mtype: size_t;
            let rand_sz: size_t;

            // determine the type of olm message and the size of the random seed
            // if the session is new and no messages have been sent to the recipient
            // the message will be larger and of type 0 (initial message).
            // if the session has encrpyted prior messages, the message type will
            // be 1 (normal message)
            unsafe {
                mtype = olm_encrypt_message_type(p.session) as size_t;
                rand_sz = olm_encrypt_random_length(p.session) as size_t;
            }

            let mut rand_buf: Vec<u8> = vec![0; rand_sz];

            // generate some random data if needed
            if rand_sz > 0 {
                unsafe {
                    randombytes_buf(rand_buf.as_mut_ptr() as *mut libc::c_void, rand_sz);
                }
            }

            let ct_sz: size_t;

            unsafe {
                // get the actual size of the encrypted key
                ct_sz = olm_encrypt_message_length(p.session, 32 + 24) as size_t;

                let last_err = session_error(p.session);

                if last_err.is_some() {
                    println!("error: {:?}", last_err.unwrap());
                    return 0;
                }
            }

            // allocate buffer for the ciphertext and encrypt the key + nonce
            let mut ct_buf: Vec<u8> = vec![0; ct_sz];

            unsafe {
                olm_encrypt(
                    p.session,
                    grp_pt.as_mut_ptr() as *mut libc::c_void,
                    grp_pt.len(),
                    rand_buf.as_mut_ptr() as *mut libc::c_void,
                    rand_sz,
                    ct_buf.as_mut_ptr() as *mut libc::c_void,
                    ct_sz,
                );

                let last_err = session_error(p.session);
                if last_err.is_some() {
                    println!("error: {:?}", last_err.unwrap());
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

        result.unwrap() as size_t
    }

    pub unsafe fn decrypt(
        &mut self,
        id: *const c_char,
        pt: *mut u8,
        pt_len: size_t,
        ct: *const u8,
        ct_len: size_t,
    ) -> size_t {
        let pid: String;

        unsafe {
            let idstr = CStr::from_ptr(id).to_str();

            if idstr.is_err() {
                println!("error: {}", idstr.unwrap_err());
                return 0;
            };

            pid = idstr.unwrap().to_string();
        }

        // get the index of the senders session
        let sp = self.participants.iter().position(|p| p.id == pid);
        if sp.is_none() {
            println!("error: participant not found in group session");
            return 0;
        }

        let spi = sp.unwrap();

        let s = self.participants[spi].session;

        // decode the group message
        let dgm = decode_group_message(ct, ct_len);
        if dgm.is_err() {
            return 0;
        }

        let gm = dgm.unwrap();

        if self.id.is_none() {
            println!("error: group session identity has not been set");
            return 0;
        }

        // get the encrypted ciphertext key from the header
        let mut mh: Option<&Message> = None;

        if let Some(ref cid) = self.id {
            mh = gm.recipients.get(cid);
        }

        if mh.is_none() {
            println!("error: message is not intended for this identity");
            return 0;
        }

        let header = mh.unwrap();

        // convert the ciphetext string to a byte array and create a second copy,
        // as olm_decrypt_max_plaintext_length mutates the buffer
        let mut ctk_buf = header.ciphertext.clone().into_bytes();
        let mut ctk_buf_cpy = header.ciphertext.clone().into_bytes();

        let ptk_sz: size_t;

        unsafe {
            // get the size of the decrypted keys plaintext
            ptk_sz = olm_decrypt_max_plaintext_length(
                s,
                header.mtype as usize,
                ctk_buf_cpy.as_mut_ptr() as *mut libc::c_void,
                ctk_buf_cpy.len(),
            ) as size_t;
        }

        let mut last_err = session_error(s);
        if last_err.is_some() {
            println!("error: {:?}", last_err.unwrap());
            return 0;
        }

        // allocate a buffer for the plaintext message key + nonce
        let mut ptk_buf: Vec<u8> = vec![0; ptk_sz];

        // decrypt the message key + nonce
        unsafe {
            olm_decrypt(
                s,
                header.mtype as usize,
                ctk_buf.as_mut_ptr() as *mut libc::c_void,
                ctk_buf.len(),
                ptk_buf.as_mut_ptr() as *mut libc::c_void,
                ptk_sz,
            );
        }

        last_err = session_error(s);
        if last_err.is_some() {
            println!("error: {:?}", last_err.unwrap());
            return 0;
        }

        // decode the group messages ciphertext from base64
        let dec = decode_config(gm.ciphertext, base64::STANDARD_NO_PAD);
        if dec.is_err() {
            println!("error: {:?}", dec.unwrap());
            return 0;
        }

        let mut dec_ct = dec.unwrap();
        let mut ptl = pt_len as c_ulonglong;

        unsafe {
            if sodium_init() == -1 {
                println!("error: sodium is not ready");
                return 0;
            }

            let ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
                pt,
                &mut ptl,
                ptr::null_mut(),
                dec_ct.as_mut_ptr(),
                dec_ct.len() as u64,
                ptr::null_mut(),
                0_u64,
                ptk_buf[32..56].as_ptr(),
                ptk_buf[0..32].as_ptr(),
            );

            if ret != 0 {
                println!("error: decrypt failed");
                return 0;
            }
        }

        ptl as usize
    }
}

fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

// get any error that may have occured from an olm session
fn session_error(s: *mut OlmSession) -> Option<String> {
    let err_str: String;

    unsafe {
        let err = olm_session_last_error(s);
        let err_str_cnv = CStr::from_ptr(err).to_str();
        err_str = String::from(err_str_cnv.unwrap());
    }

    if err_str != "SUCCESS" {
        // println!("OLM {:?}", err_str);
        return Some(err_str);
    }

    None
}
