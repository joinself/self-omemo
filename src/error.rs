use std::fmt;

#[derive(Debug, PartialEq)]
pub enum OmemoError {
    InputBufferTooSmall,
    MessageDecodeFailed,
    MessageEncodeFailed,
    MissingIdentifier,
    MissingRecipientCiphertext,
    MissingSenderSession,
    OlmDecryptFailed,
    OlmEncryptFailed,
    OutputBufferTooSmall,
    SodiumInit,
}

impl fmt::Display for OmemoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OmemoError::InputBufferTooSmall => write!(f, "input buffer too small"),
            OmemoError::MessageDecodeFailed => write!(f, "message could not be decoded"),
            OmemoError::MessageEncodeFailed => write!(f, "message could not be encoded"),
            OmemoError::MissingIdentifier => write!(f, "missing group session identifier"),
            OmemoError::MissingRecipientCiphertext => write!(
                f,
                "group message does not have a ciphertext for this recipient"
            ),
            OmemoError::MissingSenderSession => {
                write!(f, "group session is missing a session with the sender")
            }
            OmemoError::OlmDecryptFailed => write!(f, "olm decryption failed"),
            OmemoError::OlmEncryptFailed => write!(f, "olm encrypt failed"),
            OmemoError::OutputBufferTooSmall => write!(f, "output buffer too small"),
            OmemoError::SodiumInit => write!(f, "sodium init failed"),
        }
    }
}
