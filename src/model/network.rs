#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Network {
    Mainnet,
    Preprod,
    Preview,
}

impl Network {
    // Where a user can look a transaction up, without ykada.
    pub fn explorer_url(self, tx_id: &str) -> String {
        let host = match self {
            Network::Mainnet => "cardanoscan.io",
            Network::Preprod => "preprod.cardanoscan.io",
            Network::Preview => "preview.cardanoscan.io",
        };
        format!("https://{host}/transaction/{tx_id}")
    }
}
