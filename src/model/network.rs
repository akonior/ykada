#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Preprod,
    #[default]
    Preview,
}
