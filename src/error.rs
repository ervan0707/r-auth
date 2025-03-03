use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base32 decode error")]
    Base32DecodeError,

    #[error("Invalid secret key: {0}")]
    InvalidSecret(String),

    #[error("QR code error: {0}")]
    QrCode(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key parsing error: {0}")]
    KeyParse(String),

    #[error("Encryption key already exists")]
    KeyExists,

    #[error("Could not determine config directory")]
    ConfigDir,

    #[error("Age error: {0}")]
    Age(#[from] age::DecryptError),

    #[error("Storage file error: {0}")]
    StorageFile(String),

    #[error("Key file not found. Please run 'init' first")]
    KeyNotFound,

    #[error("Invalid storage data: {0}")]
    InvalidStorage(String),

    #[error("Keyring error: {0}")]
    Keyring(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;
