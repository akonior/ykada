//! Algorithm type for cryptographic algorithms supported by YubiKey

use thiserror::Error;

/// Cryptographic algorithm supported by YubiKey PIV
///
/// This type provides a type-safe way to specify cryptographic algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Ed25519 (EdDSA with Curve25519)
    Ed25519,
    /// RSA 1024-bit
    Rsa1024,
    /// RSA 2048-bit
    Rsa2048,
    /// ECDSA P-256
    EcdsaP256,
    /// ECDSA P-384
    EcdsaP384,
}

impl Algorithm {
    /// Get the default algorithm for Cardano
    ///
    /// Cardano uses Ed25519 for signatures
    pub fn default_cardano() -> Self {
        Self::Ed25519
    }

    /// Convert to yubikey crate's AlgorithmId
    pub fn to_yubikey_algorithm_id(self) -> yubikey::piv::AlgorithmId {
        match self {
            Algorithm::Ed25519 => yubikey::piv::AlgorithmId::Ed25519,
            Algorithm::Rsa1024 => yubikey::piv::AlgorithmId::Rsa1024,
            Algorithm::Rsa2048 => yubikey::piv::AlgorithmId::Rsa2048,
            Algorithm::EcdsaP256 => yubikey::piv::AlgorithmId::EccP256,
            Algorithm::EcdsaP384 => yubikey::piv::AlgorithmId::EccP384,
        }
    }

    /// Convert from yubikey crate's AlgorithmId
    ///
    /// # Errors
    ///
    /// Returns `AlgorithmError::Unsupported` if the algorithm is not supported by ykada
    pub fn from_yubikey_algorithm_id(
        alg: yubikey::piv::AlgorithmId,
    ) -> Result<Self, AlgorithmError> {
        match alg {
            yubikey::piv::AlgorithmId::Ed25519 => Ok(Algorithm::Ed25519),
            yubikey::piv::AlgorithmId::Rsa1024 => Ok(Algorithm::Rsa1024),
            yubikey::piv::AlgorithmId::Rsa2048 => Ok(Algorithm::Rsa2048),
            yubikey::piv::AlgorithmId::EccP256 => Ok(Algorithm::EcdsaP256),
            yubikey::piv::AlgorithmId::EccP384 => Ok(Algorithm::EcdsaP384),
            _ => Err(AlgorithmError::Unsupported {
                algorithm: format!("{:?}", alg),
            }),
        }
    }
}

/// Errors that can occur when working with algorithms
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmError {
    /// Algorithm is not supported by ykada
    #[error("Algorithm not supported: {algorithm}")]
    Unsupported { algorithm: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_conversion() {
        let alg = Algorithm::Ed25519;
        let yubikey_alg = alg.to_yubikey_algorithm_id();
        assert_eq!(yubikey_alg, yubikey::piv::AlgorithmId::Ed25519);
    }

    #[test]
    fn test_algorithm_from_yubikey() {
        let yubikey_alg = yubikey::piv::AlgorithmId::Ed25519;
        let alg = Algorithm::from_yubikey_algorithm_id(yubikey_alg).unwrap();
        assert_eq!(alg, Algorithm::Ed25519);
    }

    #[test]
    fn test_default_cardano() {
        assert_eq!(Algorithm::default_cardano(), Algorithm::Ed25519);
    }

    #[test]
    fn test_algorithm_error_display() {
        let err = AlgorithmError::Unsupported {
            algorithm: "Unknown".to_string(),
        };
        assert!(err.to_string().contains("not supported"));
    }
}
