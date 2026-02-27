#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Preprod,
    Preview,
}

impl Default for Network {
    fn default() -> Self {
        Self::Preview
    }
}
