use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath(bip32::DerivationPath);

#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("Invalid derivation path")]
pub struct DerivationPathError {
    #[from]
    source: bip32::Error,
}

impl TryFrom<&str> for DerivationPath {
    type Error = DerivationPathError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        let bip32_path = path.parse::<bip32::DerivationPath>()?;
        Ok(DerivationPath(bip32_path))
    }
}

impl DerivationPath {
    pub fn indices(&self) -> Vec<u32> {
        self.0.iter().map(|child| child.0).collect()
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        DerivationPath::try_from("m/1852'/1815'/0'/0/0").expect("Default derivation path is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_path() {
        let path = DerivationPath::default();
        assert_eq!(
            path.indices(),
            vec![0x8000_073C, 0x8000_0717, 0x8000_0000, 0, 0]
        );
    }

    #[test]
    fn test_parse_cip1852_path() {
        let path_str = "m/1852'/1815'/0'/0/0";
        let path = DerivationPath::try_from(path_str).unwrap();
        assert_eq!(
            path.indices(),
            vec![0x8000_073C, 0x8000_0717, 0x8000_0000, 0, 0]
        );
    }

    #[test]
    fn test_parse_drep_path() {
        let path_str = "m/1852'/1815'/0'/3/0";
        let path = DerivationPath::try_from(path_str).unwrap();
        assert_eq!(
            path.indices(),
            vec![0x8000_073C, 0x8000_0717, 0x8000_0000, 3, 0]
        );
    }

    #[test]
    fn test_invalid_path_no_m() {
        let result = DerivationPath::try_from("1852'/1815'/0'/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_index() {
        let result = DerivationPath::try_from("m/1852'/invalid'/0'/0/0");
        assert!(result.is_err());
    }
}
