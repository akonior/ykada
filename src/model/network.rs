#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Network {
    Mainnet,
    Preprod,
    Preview,
}
