#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxHash([u8; 32]);

impl TxHash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
