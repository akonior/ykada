use crate::error::{YkadaError, YkadaResult};

pub(crate) fn check_firmware_version(version: (u8, u8, u8)) -> YkadaResult<()> {
    let (major, minor, _) = version;
    if (major, minor) >= (5, 7) {
        Ok(())
    } else {
        Err(YkadaError::FirmwareIncompatible { found: version })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_5_7_and_newer() {
        assert!(check_firmware_version((5, 7, 0)).is_ok());
        assert!(check_firmware_version((6, 0, 0)).is_ok());
    }

    #[test]
    fn test_rejects_older_than_5_7() {
        assert!(matches!(
            check_firmware_version((5, 6, 9)).unwrap_err(),
            YkadaError::FirmwareIncompatible { found: (5, 6, 9) }
        ));
    }
}
