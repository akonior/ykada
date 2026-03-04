pub enum SendMode {
    DryRun,
    SignOnly,
    SignAndSubmit,
}

pub enum SendOutcome {
    Cbor(Vec<u8>),
    TxHash(String),
}
