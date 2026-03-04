use thiserror::Error;

pub struct DerPrivateKey(pub Vec<u8>);

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterialError {
    #[error("Key must be exactly {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}
