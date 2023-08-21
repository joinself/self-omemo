// Copyright 2020 Self Group Ltd. All Rights Reserved.

extern crate libc;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::OmemoError;

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
#[derive(Serialize, Deserialize)]
pub struct GroupMessage {
    pub recipients: HashMap<String, Message>,
    pub ciphertext: String,
}

impl Message {
    pub fn new(mtype: i64, ciphertext: String) -> Message {
        Message { mtype, ciphertext }
    }
}

impl GroupMessage {
    pub fn new(ciphertext: String) -> GroupMessage {
        GroupMessage {
            recipients: HashMap::new(),
            ciphertext,
        }
    }

    pub fn decode(message: &[u8]) -> serde_json::Result<GroupMessage> {
        serde_json::from_reader(message)
    }

    pub fn encode(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

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
    serde_json::from_slice(buf)
}

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
