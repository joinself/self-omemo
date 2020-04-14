extern crate libc;
extern crate base64;

include!(concat!(env!("OUT_DIR"), "/olm.rs"));

use std::slice;
use std::ffi::CString;
use base64::{encode_config};
use sodiumoxide::crypto::aead::chacha20poly1305;
use crate::group_message::GroupMessage;

#[repr(C)] pub struct Account { _private: [u8; 0] }
#[repr(C)] pub struct Session { _private: [u8; 0] }

pub struct GroupSession{
    participants: Vec<Participant>,
}

struct Participant {
    id: String,
    session: *mut Session,
}

impl GroupSession {
    #[no_mangle]
    pub unsafe extern "C" fn  new() -> *mut GroupSession {
        return &mut GroupSession{
            participants: Vec::new(),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn add_participant(&mut self, id: *mut i8, participant: *mut Session) -> size_t {
        let idstr = CString::from_raw(id);
        let pid = idstr.into_string();

        if pid.is_err() {
            return 1;
        };

        self.participants.push(Participant{
            id: pid.unwrap(),
            session: participant,
        });

        return 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn encrypted_size(&mut self, ptlen: size_t) -> size_t {
        let ptsz = ptlen as usize;

        // TODO: calculate base64 encoding of ciphertext

        // include 16 byte validation tag
        let pt = String::from_utf8(vec![b'X'; ptsz+16]);
        if pt.is_err() {
            return 0;
        }

        // create mock recipient key
        let ky = String::from_utf8(vec![b'X'; 289]);
        if pt.is_err() {
            return 0;
        }

        let key = ky.unwrap();

        let mut gm = GroupMessage::new(pt.unwrap());

        for p in &self.participants {
            gm.add_recipient(p.id.clone(), key.clone());
        }

        let res = gm.encode();

        if res.is_err() {
            return 0;
        }

        let alen = res.unwrap().len();

        return alen as size_t;
    }

    pub unsafe extern "C" fn encrypt(&mut self, pt: *const u8, ptlen: size_t, ct: *mut u8, ctlen: size_t) -> size_t {
        assert!(!pt.is_null(), "plaintext buffer must not be null");
        assert!(!ct.is_null(), "ciphertext buffer must not be null");
        assert!(self.encrypted_size(ptlen) == ctlen, "ciphertext buffer is not big enough");

        let ptb: &[u8] = slice::from_raw_parts(pt, ptlen as usize);

        let k = chacha20poly1305::gen_key();
        let n = chacha20poly1305::gen_nonce();

        let ctb = chacha20poly1305::seal(ptb, None, &n, &k);

        let encct = encode_config(ctb, base64::STANDARD_NO_PAD);

        let mut gm = GroupMessage::new(encct);

        for p in &self.participants {
            //p.session

            gm.add_recipient(p.id.clone(), key.clone());
        }

        return 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn create_group_session() -> *mut GroupSession {
    return GroupSession::new();
    //return olm_account_size();
}
