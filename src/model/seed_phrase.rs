use std::fmt;

use bip39::{Language, Mnemonic};
use thiserror::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct SeedPhrase(Mnemonic);

// Never print the mnemonic via Debug (e.g. in a panic backtrace or struct dump).
impl fmt::Debug for SeedPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SeedPhrase([REDACTED])")
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SeedPhraseError {
    #[error("Invalid mnemonic")]
    InvalidMnemonic(#[from] bip39::Error),
    #[error("OS entropy source unavailable")]
    EntropyUnavailable(rand_core::OsError),
}

impl TryFrom<&str> for SeedPhrase {
    type Error = SeedPhraseError;

    fn try_from(phrase: &str) -> Result<Self, Self::Error> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)?;
        Ok(SeedPhrase(mnemonic))
    }
}

impl SeedPhrase {
    pub fn entropy(&self) -> Vec<u8> {
        self.0.to_entropy()
    }

    // Not pure: uses OS entropy.
    pub fn generate() -> Result<Self, SeedPhraseError> {
        use rand_core::{OsRng, TryRngCore};
        let mut entropy = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut entropy)
            .map_err(SeedPhraseError::EntropyUnavailable)?;
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
        Ok(SeedPhrase(mnemonic))
    }

    pub fn phrase(&self) -> String {
        self.0.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{KNOWN_PHRASE, TEST_PHRASE};

    #[test]
    fn test_12_word_mnemonic() {
        assert!(SeedPhrase::try_from(TEST_PHRASE).is_ok());
    }

    #[test]
    fn test_invalid_word_count() {
        let phrase = "test walk nut";
        let result = SeedPhrase::try_from(phrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_mnemonic() {
        let phrase = "invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid";
        let result = SeedPhrase::try_from(phrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_redacted() {
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let debug_str = format!("{seed:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("walk"));
    }

    #[test]
    fn test_24_word_entropy_vector() {
        let result = SeedPhrase::try_from(KNOWN_PHRASE);
        assert!(result.is_ok(), "error: {:?}", result.err());

        let entropy = result.unwrap().entropy();
        assert_eq!(entropy.len(), 32);
        assert_eq!(
            entropy,
            hex::decode("23413ca02364962ed21a30444ab9b58b733bc3389a938e53037e8c89931a6711")
                .unwrap()
        );
    }
}
