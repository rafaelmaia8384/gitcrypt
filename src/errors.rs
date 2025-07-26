use thiserror::Error;

#[derive(Error, Debug)]
pub enum GitCryptError {
    #[error("IO error: {0}")]
    IoError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Directory creation failed: {0}")]
    DirectoryCreationFailed(String),

    #[error("Base58 decoding error: {0}")]
    Base58DecodeError(String),

    #[error("Path error: {0}")]
    PathError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<std::io::Error> for GitCryptError {
    fn from(error: std::io::Error) -> Self {
        GitCryptError::IoError(error.to_string())
    }
}

impl From<serde_json::Error> for GitCryptError {
    fn from(error: serde_json::Error) -> Self {
        GitCryptError::SerializationError(error.to_string())
    }
}

impl From<aes_gcm::Error> for GitCryptError {
    fn from(error: aes_gcm::Error) -> Self {
        GitCryptError::EncryptionError(error.to_string())
    }
}
