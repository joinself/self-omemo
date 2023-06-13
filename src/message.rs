// Copyright 2020 Self Group Ltd. All Rights Reserved.

extern crate libc;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Result};
use libc::{size_t};
use std::ptr;

// Message is the containing structure for a message to an individual recipient
// macro to set this struct to as serializable by serde, the encoding library
#[derive(Serialize, Deserialize)]
pub struct Message {
    pub mtype: i64,
    pub ciphertext: String,
}

// GroupMessage holds the ciphertext that is shared for multiple recipients, as well as
// the encrypted keys for each recipient that opens the ciphertext.
// when serialized to json, this message will look like:
// {
//     "recipients": {
//         "alice:1": {
//              "mtype": 0,
//              "ciphertext": "encryptedKeyforCiphertextMessage"
//          },
//         "bob:1": {
//              "mtype": 1,
//              "ciphertext": "encryptedKeyforCiphertextMessage"
//          },
//     },
//     "ciphertext": "ciphertextMessage"
// }
// macro to set this struct to as serializable by serde, the encoding library
#[derive(Serialize, Deserialize)]
pub struct GroupMessage {
    pub recipients: HashMap<String, Message>,
    pub ciphertext: String,
}

// impl blocks are used to declare functions on struct, similar to receiver functions in go
impl Message{
    pub fn new(mtype: i64, ciphertext: String) -> Message {
        Message{
            mtype,
            ciphertext,
        }
    }
}

// impl blocks are used to declare functions on struct, similar to receiver functions in go

impl GroupMessage{
    pub fn new(ciphertext: String) -> GroupMessage {
        GroupMessage{
            recipients: HashMap::new(),
            ciphertext,
        }
    }

    // self in this context is a pointer to the group message struct
    // its actually not a parameter you have to pass in when calling this function
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    // Result is a tuple that gets returned that wrap an value or an error. It's similar to returning (value, error) in go
    // you can call .is_err() to check if there is an error, or you can .unwrap() the result to get the value
    pub unsafe fn encode_to_buffer(&self, buf: *mut u8, buf_len: usize) -> Result<size_t>{
        let j = serde_json::to_vec(self);

        if j.is_err() {
            return Err(j.err().unwrap())
        };

        let mut result = j.unwrap();

        // this is an assertion that will panic if not true
        // the 'as' syntax is used to cast from one type to another
        // in this case, its casting from u64 -> usize
        assert!(buf_len >= result.len(), "buffer size is too small");

        // rust enforces strict guarantees around memory safety.
        // the compiler will check that the memory you are accessing is valid
        // some scenarios the compiler can't check.
        // in this case, we are attempting to copy from memory allocated in rust
        // to memory allocated in c. The compiler can't determine if the memory
        // its copying to is valid, so we use this unsafe block to tell the compiler
        // to relax some of its checks.
            ptr::copy(result.as_mut_ptr(), buf, result.len());


        // return an ok result containing the size of the data written to the buffer
        Ok(result.len())
    }

    pub fn add_recipient(&mut self, recipient: String, msg: Message) {
        self.recipients.insert(recipient, msg);
    }
}


// size_t here is not a native rust type, its a c type we need for the interface
// its basically an architecture independent c type for representing an integer that
// will work for both 32 and 64 bit systems
pub unsafe fn encode_group_message(group_message: GroupMessage, buf: *mut u8) -> size_t {
    // encodes the group message as a byte array
    let j = serde_json::to_vec(&group_message);

    if j.is_err() {
        return 1
    };

    let mut result = j.unwrap();


        ptr::copy(result.as_mut_ptr(), buf, result.len());


    0
}

pub unsafe fn decode_group_message(buf: *const u8, len: usize) -> Result<GroupMessage> {
    let mut dst = Vec::with_capacity(len);

    // copy the encoded json buffer to a rust slice
    dst.set_len(len);
    ptr::copy(buf, dst.as_mut_ptr(), len);

    // deserialize the vector to a group message struct
    let gm: GroupMessage = serde_json::from_slice(dst.as_slice())?;

    Ok(gm)
}

// unit tests are normally written in the same file as the implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_group_message() {
        let ct = "test".to_string();
        let gm = GroupMessage::new(ct);
        let body = gm.encode();
        assert!(body.is_ok());
    }

    #[test]
    fn group_message_add_recipient() {
        let ct = "test".to_string();
        let mut gm = GroupMessage::new(ct);

        gm.add_recipient(String::from("test-recipient"), Message::new(0, String::from("test-ciphertext-key")));

        let recip = gm.recipients.get(&String::from("test-recipient"));
        if let Some(k) = &recip {
            assert_eq!(String::from("test-ciphertext-key"), k.ciphertext);
        }
    }
}
