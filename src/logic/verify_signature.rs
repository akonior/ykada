use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::{YkadaError, YkadaResult};

// Verify an Ed25519 signature over `message` against `vkey`. Used to confirm the
// YubiKey returned a correct signature before a tx is assembled or submitted —
// a faulty/wrong-slot device must never produce a broadcastable transaction.
pub(crate) fn verify_signature(vkey: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> YkadaResult<()> {
    VerifyingKey::from_bytes(vkey)?
        .verify_strict(message, &Signature::from_bytes(sig))
        .map_err(|_| YkadaError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn accepts_valid_signature() {
        let sk = signing_key(7);
        let msg = b"transaction body hash";
        let sig = sk.sign(msg).to_bytes();
        assert!(verify_signature(&sk.verifying_key().to_bytes(), msg, &sig).is_ok());
    }

    #[test]
    fn rejects_tampered_message() {
        let sk = signing_key(7);
        let sig = sk.sign(b"original").to_bytes();
        let err = verify_signature(&sk.verifying_key().to_bytes(), b"tampered", &sig).unwrap_err();
        assert!(matches!(err, YkadaError::SignatureVerificationFailed));
    }

    #[test]
    fn rejects_wrong_key() {
        let sk = signing_key(7);
        let msg = b"msg";
        let sig = sk.sign(msg).to_bytes();
        let other_vk = signing_key(9).verifying_key().to_bytes();
        assert!(verify_signature(&other_vk, msg, &sig).is_err());
    }
}
