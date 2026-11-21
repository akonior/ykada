// PUBLIC TEST VECTORS — never fund these wallets.
pub(crate) const TEST_PHRASE: &str =
    "test walk nut penalty hip pave soap entry language right filter choice";

pub(crate) const KNOWN_PHRASE: &str = "cash antique chimney egg enact blast embody ecology dust fiction hope black crisp thunder tiny fame mixture object text boil odor minor ordinary deer";
pub(crate) const KNOWN_ADDRESS_MAINNET: &str = "addr1qx2l2ttwpsxc8j4830x7hpz0qgaf2hkt6dn7x940vcneycwcnz39fcfw4xs5elpnpmfmh45vhx2qk3h8q56ma0zg9nnsvzxxtr";

pub(crate) const RECIPIENT: &str = "addr_test1qrfw6ye0m7f2kvqapnkp7jzlfydq0h6j5rnsvj2wm9vlhg0y86x894xrsh5xu8qlm6yld03hp7sx6u552w6uupd799fqz0vpte";

// A transaction signed by ykada on a YubiKey and confirmed on Preview.
pub(crate) const ON_CHAIN_TX_ID: &str =
    "4aa9417442e9b042075472a425516314005f6c3aeec80a477405420d06200a44";
pub(crate) const ON_CHAIN_TX_CBOR: &str = include_str!("../tests/fixtures/preview-signed-tx.hex");
