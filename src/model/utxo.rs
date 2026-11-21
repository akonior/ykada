pub struct Utxo {
    pub tx_hash: String,
    pub tx_index: u64,
    pub lovelace: u64,
    pub has_tokens: bool,
}
