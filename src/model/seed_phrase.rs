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

// The messages never quote a word of the phrase: errors end up in terminals and logs.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SeedPhraseError {
    #[error("{0}")]
    InvalidMnemonic(String),
    #[error("OS entropy source unavailable")]
    EntropyUnavailable(getrandom::Error),
}

impl From<bip39::Error> for SeedPhraseError {
    fn from(e: bip39::Error) -> Self {
        SeedPhraseError::InvalidMnemonic(match e {
            bip39::Error::BadWordCount(n) => {
                format!("it has {n} words; a mnemonic has 12, 15, 18, 21 or 24")
            }
            bip39::Error::UnknownWord(index) => {
                format!("word {} is not in the BIP39 English word list", index + 1)
            }
            bip39::Error::InvalidChecksum => {
                "the checksum doesn't match: a word is wrong, or two words are swapped".into()
            }
            bip39::Error::BadEntropyBitCount(_) | bip39::Error::AmbiguousLanguages(_) => {
                "it is not a valid BIP39 mnemonic".into()
            }
        })
    }
}

// Accepts the phrase as people type or save it: any case, any spacing, a leading BOM.
impl TryFrom<&str> for SeedPhrase {
    type Error = SeedPhraseError;

    fn try_from(phrase: &str) -> Result<Self, Self::Error> {
        let normalized = phrase.trim_start_matches('\u{feff}').to_lowercase();
        let mnemonic = Mnemonic::parse_in(Language::English, normalized.as_str())?;
        Ok(SeedPhrase(mnemonic))
    }
}

impl SeedPhrase {
    pub fn entropy(&self) -> Vec<u8> {
        self.0.to_entropy()
    }

    // Not pure: uses OS entropy.
    pub fn generate() -> Result<Self, SeedPhraseError> {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).map_err(SeedPhraseError::EntropyUnavailable)?;
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

    // Numbered from 1, as people count words, and never quoting the word itself.
    #[test]
    fn test_unknown_word_is_numbered_from_one_and_not_quoted() {
        let phrase = TEST_PHRASE.replacen("test", "zzzzzz", 1);
        let msg = SeedPhrase::try_from(phrase.as_str())
            .unwrap_err()
            .to_string();
        assert_eq!(msg, "word 1 is not in the BIP39 English word list");
    }

    #[test]
    fn test_wrong_word_count_is_explained() {
        let msg = SeedPhrase::try_from("test walk nut")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("it has 3 words"), "got: {msg}");
    }

    #[test]
    fn test_swapped_words_fail_the_checksum() {
        let words: Vec<&str> = TEST_PHRASE.split_whitespace().collect();
        let swapped = [&[words[1], words[0]][..], &words[2..]].concat().join(" ");
        let msg = SeedPhrase::try_from(swapped.as_str())
            .unwrap_err()
            .to_string();
        assert!(msg.contains("checksum"), "got: {msg}");
    }

    #[test]
    fn test_upper_case_and_a_bom_are_the_same_phrase() {
        let shouted = format!("\u{feff}{}", TEST_PHRASE.to_uppercase());
        assert_eq!(
            SeedPhrase::try_from(shouted.as_str()).unwrap(),
            SeedPhrase::try_from(TEST_PHRASE).unwrap()
        );
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
