extern crate libc;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Result;
use libc::{size_t};
use std::ptr;

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub mtype: i64,
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize)]
pub struct GroupMessage {
    pub recipients: HashMap<String, Message>,
    pub ciphertext: String,
}

impl Message{
    pub fn new(mtype: i64, ciphertext: String) -> Message {
        return Message{
            mtype: mtype,
            ciphertext: ciphertext,
        }
    }
}

impl GroupMessage{
    pub fn new(ciphertext: String) -> GroupMessage {
        return GroupMessage{
            recipients: HashMap::new(),
            ciphertext: ciphertext,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        return serde_json::to_vec(self);
    }

    pub fn encode_to_buffer(&self, buf: *mut u8, buf_len: u64) -> Result<size_t>{
        let j = serde_json::to_vec(self);

        if j.is_err() {
            return Err(j.err().unwrap())
        };

        let mut result = j.unwrap();

        assert!(buf_len as usize >= result.len(), "buffer size is too small");

        unsafe {
            ptr::copy(result.as_mut_ptr(), buf, result.len());
        }

        return Ok(result.len());
    }

    pub fn add_recipient(&mut self, recipient: String, msg: Message) {
        self.recipients.insert(recipient, msg);
    }
}

pub fn encode_group_message(group_message: GroupMessage, buf: *mut u8) -> size_t {
    let j = serde_json::to_vec(&group_message);

    if j.is_err() {
        return 1
    };

    let mut result = j.unwrap();

    unsafe {
        ptr::copy(result.as_mut_ptr(), buf, result.len());
    }

    return 0
}

pub fn decode_group_message(buf: *const u8, len: usize) -> Result<GroupMessage> {
    let mut dst = Vec::with_capacity(len);

    unsafe {
        dst.set_len(len);
        ptr::copy(buf, dst.as_mut_ptr(), len);
    }

    let gm: GroupMessage = serde_json::from_slice(dst.as_slice())?;

    return Ok(gm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_group_message() {
        let ct = "test".to_string();
        let gm = GroupMessage::new(ct);
        let body = gm.encode();
        assert_eq!(body.is_ok(), true);
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
