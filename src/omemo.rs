// Copyright 2020 Self Group Ltd. All Rights Reserved.

use std::ffi::CStr;
use std::ptr;

use base64::{decode_config, encode_config};
use libc::{c_ulonglong, size_t};
use olm_sys::*;
use sodium_sys::*;

use crate::error::OmemoError;
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
    pub fn new() -> GroupSession {
        GroupSession {
            id: None,
            participants: Vec::new(),
        }
    }

    pub unsafe fn set_identity(&mut self, id: String) {
        self.id = Some(id);
    }

    // add a participcant and their session to the group session
    pub unsafe fn add_participant(&mut self, id: String, s: *mut crate::olm::OlmSession) {
        self.participants.push(Participant {
            id,
            session: (*s).ptr(),
        });
    }

    // returns the size of an encrypted message based on the plaintext size
    pub unsafe fn encrypted_size(&mut self, pt_len: usize) -> Result<usize, OmemoError> {
        // generate a fake encoded message
        // include 16 byte validation tag
        let pt_sz = sodium_base64_encoded_len(
            pt_len + 24,
            sodium_base64_VARIANT_ORIGINAL_NO_PADDING as i32,
        );

        let mut gm = GroupMessage::new(
            String::from_utf8(vec![b'X'; pt_sz]).expect("failed to build string"),
        );

        // iterate over each participant and add a fake
        // encrypted key as its value
        for p in &self.participants {
            // get the size of the ciphertext thats encrypted
            // by the olm session. the olm session
            // will be encrypting the key and nonce used
            // to generate the main messages ciphertext

            let enc_sz = olm_encrypt_message_length(p.session, 32 + 24) as size_t;

            // create mock recipient ciphertext
            let ky = String::from_utf8(vec![b'X'; enc_sz]).expect("failed to build string");

            gm.add_recipient(p.id.clone(), Message::new(0, ky));
        }

        // encode the fake message and return its size
        match gm.encode() {
            Ok(encoded) => Ok(encoded.len()),
            Err(_) => Err(OmemoError::MessageEncodeFailed),
        }
    }

    // returns the size of the paintext message based on the ciphertext
    pub unsafe fn decrypted_size(&mut self, ct: &[u8]) -> usize {
        // plaintext size is the messages ciphertext size minus the 16
        // bytes used by the cipher to authenticate the message
        match decode_group_message(ct) {
            Ok(gm) => gm.ciphertext.len() - 16,
            Err(_) => 0,
        }
    }

    // encrypt a message
    pub unsafe fn encrypt(&mut self, pt: &[u8], ct: &mut [u8]) -> Result<usize, OmemoError> {
        // setup message ciphertext, key and nonce buffer
        let mut ctb: Vec<u8> = vec![0; pt.len() + 16];
        let mut ctbl = ctb.len() as c_ulonglong;
        let mut kb: Vec<u8> = vec![0; 32];
        let mut nb: Vec<u8> = vec![0; 24];

        if sodium_init() == -1 {
            return Err(OmemoError::SodiumInit);
        }

        // create group message key
        crypto_aead_xchacha20poly1305_ietf_keygen(kb.as_mut_ptr());
        randombytes_buf(nb.as_mut_ptr() as *mut libc::c_void, 24);

        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ctb.as_mut_ptr(),
            &mut ctbl,
            pt.as_ptr(),
            pt.len() as u64,
            ptr::null(),
            0_u64,
            ptr::null_mut(),
            nb.as_mut_ptr(),
            kb.as_mut_ptr(),
        );

        ctb.set_len(ctbl as usize);

        // encode the ciphertext to base64
        let mut gm = GroupMessage::new(encode_config(ctb, base64::STANDARD_NO_PAD));

        // join the key and nonce together
        let mut grp_pt = concat_u8(kb.as_ref(), nb.as_ref());

        // encrypt group message key with participants olm sessions
        for p in &self.participants {
            // determine the type of olm message and the size of the random seed
            // if the session is new and no messages have been sent to the recipient
            // the message will be larger and of type 0 (initial message).
            // if the session has encrpyted prior messages, the message type will
            // be 1 (normal message)
            let mtype = olm_encrypt_message_type(p.session);
            let rand_len = olm_encrypt_random_length(p.session);
            let mut rand_buf: Vec<u8> = vec![0; rand_len];

            // generate some random data if needed
            if rand_len > 0 {
                randombytes_buf(rand_buf.as_mut_ptr() as *mut libc::c_void, rand_len);
            }

            // get the actual size of the encrypted key
            let ct_sz = olm_encrypt_message_length(p.session, 32 + 24);
            if session_error(p.session).is_some() {
                return Err(OmemoError::OlmEncryptFailed);
            };

            // allocate buffer for the ciphertext and encrypt the key + nonce
            let mut ct_buf: Vec<u8> = vec![0; ct_sz];

            olm_encrypt(
                p.session,
                grp_pt.as_mut_ptr() as *mut libc::c_void,
                grp_pt.len(),
                rand_buf.as_mut_ptr() as *mut libc::c_void,
                rand_len,
                ct_buf.as_mut_ptr() as *mut libc::c_void,
                ct_sz,
            );

            if session_error(p.session).is_some() {
                return Err(OmemoError::OlmEncryptFailed);
            }

            // add encrypted key + nonce to group message
            gm.add_recipient(
                p.id.clone(),
                Message::new(
                    mtype as i64,
                    String::from_utf8(ct_buf).expect("failed to trim unused space"),
                ),
            );
        }

        // copy encoded json to ciphertext buffer
        let result = gm.encode_to_buffer(ct);
        if result.is_err() {
            return Err(OmemoError::MessageEncodeFailed);
        }

        Ok(result.unwrap() as size_t)
    }

    pub unsafe fn decrypt(
        &mut self,
        id: &str,
        pt: &mut [u8],
        ct: &[u8],
    ) -> Result<usize, OmemoError> {
        let identifier = match &self.id {
            Some(id) => id,
            None => {
                println!("error: group session identity has not been set");
                return Err(OmemoError::MissingIdentifier);
            }
        };

        // get the index of the senders session
        let sender_session = match self.participants.iter().position(|p| p.id == id) {
            Some(pos) => self.participants[pos].session,
            None => {
                println!("error: participant not found in group session");
                return Err(OmemoError::MissingSenderSession);
            }
        };

        // decode the group message
        let group_message = match decode_group_message(ct) {
            Ok(gm) => gm,
            Err(err) => {
                println!("error: could not decode message: {}", err);
                return Err(OmemoError::MessageDecodeFailed);
            }
        };

        let message_hdr = match group_message.recipients.get(identifier) {
            Some(hdr) => hdr,
            None => {
                println!("error: message is not intended for this identity");
                return Err(OmemoError::MissingRecipientCiphertext);
            }
        };

        // convert the ciphetext string to a byte array and create a second copy,
        // as olm_decrypt_max_plaintext_length mutates the buffer
        let mut ctk_buf = message_hdr.ciphertext.clone().into_bytes();
        let mut ctk_buf_cpy = message_hdr.ciphertext.clone().into_bytes();

        // get the size of the decrypted keys plaintext
        let ptk_sz = olm_decrypt_max_plaintext_length(
            sender_session,
            message_hdr.mtype as usize,
            ctk_buf_cpy.as_mut_ptr() as *mut libc::c_void,
            ctk_buf_cpy.len(),
        );

        if session_error(sender_session).is_some() {
            return Err(OmemoError::OlmDecryptFailed);
        }

        // allocate a buffer for the plaintext message key + nonce
        let mut ptk_buf: Vec<u8> = vec![0; ptk_sz];

        // decrypt the message key + nonce
        olm_decrypt(
            sender_session,
            message_hdr.mtype as usize,
            ctk_buf.as_mut_ptr() as *mut libc::c_void,
            ctk_buf.len(),
            ptk_buf.as_mut_ptr() as *mut libc::c_void,
            ptk_sz,
        );

        if session_error(sender_session).is_some() {
            return Err(OmemoError::OlmDecryptFailed);
        }

        // decode the group messages ciphertext from base64
        let mut decoded = match decode_config(group_message.ciphertext, base64::STANDARD_NO_PAD) {
            Ok(decoded) => decoded,
            Err(_) => return Err(OmemoError::MessageDecodeFailed),
        };

        let mut ptl = pt.len() as c_ulonglong;

        if sodium_init() == -1 {
            return Err(OmemoError::SodiumInit);
        }

        let ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.as_mut_ptr(),
            &mut ptl,
            ptr::null_mut(),
            decoded.as_mut_ptr(),
            decoded.len() as u64,
            ptr::null_mut(),
            0_u64,
            ptk_buf[32..56].as_ptr(),
            ptk_buf[0..32].as_ptr(),
        );

        if ret != 0 {
            println!("error: decrypt failed");
            return Err(OmemoError::OlmDecryptFailed);
        }

        Ok(ptl as usize)
    }
}

impl Default for GroupSession {
    fn default() -> Self {
        Self::new()
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
