pub struct AccountBalance {
    pub lovelace: u64,
    pub tokens: Vec<TokenBalance>,
}

pub struct TokenBalance {
    pub policy_id: String,
    pub asset_name: String,
    pub quantity: u64,
}

impl AccountBalance {
    pub fn ada(&self) -> f64 {
        self.lovelace as f64 / 1_000_000.0
    }
}
