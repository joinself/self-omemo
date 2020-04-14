extern crate libc;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Result;
use libc::{size_t};
use std::ptr;

#[derive(Serialize, Deserialize)]
pub struct GroupMessage {
    pub recipients: HashMap<String, String>,
    pub ciphertext: String,
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

    pub fn encode_to_buffer(&self, buf: *mut u8) -> Result<()>{
        let j = serde_json::to_vec(self);

        if j.is_err() {
            return Err(j.err().unwrap())
        };

        let mut result = j.unwrap();

        unsafe {
            ptr::copy(result.as_mut_ptr(), buf, result.len());
        }

        return Ok(())
    }

    pub fn add_recipient(&mut self, recipient: String, ct_key: String) {
        self.recipients.insert(recipient, ct_key);
    }
}


fn encode_group_message(group_message: GroupMessage, buf: *mut u8) -> size_t {
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

fn decode_group_message(buf: *const u8, len: usize) -> Result<GroupMessage> {
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

        gm.add_recipient(String::from("test-recipient"), String::from("test-ciphertext-key"));

        let recip = gm.recipients.get(&String::from("test-recipient"));
        if let Some(k) = &recip {
            assert_eq!(&String::from("test-ciphertext-key"), *k);
        }
    }
}
