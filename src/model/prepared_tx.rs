use crate::model::Network;

// A transaction checked and ready to sign: built by `send`, or read by `sign-tx`. Everything
// that can fail without the PIN has been checked, so the PIN is asked for only after this.
pub struct PreparedTx {
    pub(crate) cbor: Vec<u8>,
    pub(crate) payment_vkey: [u8; 32],
    pub(crate) network: Network,
}
