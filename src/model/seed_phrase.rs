use bip39::{Language, Mnemonic};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedPhrase(Mnemonic);

#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("Invalid mnemonic")]
pub struct SeedPhraseError {
    #[from]
    source: bip39::Error,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_12_word_mnemonic() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase);
        assert!(seed.is_ok());
    }

    #[test]
    fn test_24_word_mnemonic() {
        let phrase = "excess behave track soul table wear ocean cash stay nature item turtle palm soccer lunch horror start stumble month panic right must lock dress";
        let seed = SeedPhrase::try_from(phrase);
        assert!(seed.is_ok());
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
}
