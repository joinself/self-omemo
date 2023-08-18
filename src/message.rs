// Copyright 2020 Self Group Ltd. All Rights Reserved.

extern crate libc;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::OmemoError;

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
impl Message {
    pub fn new(mtype: i64, ciphertext: String) -> Message {
        Message { mtype, ciphertext }
    }
}

// impl blocks are used to declare functions on struct, similar to receiver functions in go

impl GroupMessage {
    pub fn new(ciphertext: String) -> GroupMessage {
        GroupMessage {
            recipients: HashMap::new(),
            ciphertext,
        }
    }

    // self in this context is a pointer to the group message struct
    // its actually not a parameter you have to pass in when calling this function
    pub fn encode(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    // Result is a tuple that gets returned that wrap an value or an error. It's similar to returning (value, error) in go
    // you can call .is_err() to check if there is an error, or you can .unwrap() the result to get the value
    pub unsafe fn encode_to_buffer(&self, buf: &mut [u8]) -> Result<usize, OmemoError> {
        if let Ok(encoded) = serde_json::to_vec(self) {
            assert!(buf.len() >= encoded.len(), "buffer size is too small");
            buf[..encoded.len()].copy_from_slice(&encoded);
            return Ok(encoded.len());
        }

        Err(OmemoError::MessageDecodeFailed)
    }

    pub fn add_recipient(&mut self, recipient: String, msg: Message) {
        self.recipients.insert(recipient, msg);
    }

    pub fn decrypted_size(&self) -> usize {
        self.ciphertext.len() - 16
    }
}

pub unsafe fn decode_group_message(buf: &[u8]) -> serde_json::Result<GroupMessage> {
    // deserialize the vector to a group message struct
    serde_json::from_slice(buf)
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

        gm.add_recipient(
            String::from("test-recipient"),
            Message::new(0, String::from("test-ciphertext-key")),
        );

        let recip = gm.recipients.get(&String::from("test-recipient"));
        if let Some(k) = &recip {
            assert_eq!(String::from("test-ciphertext-key"), k.ciphertext);
        }
    }
}
