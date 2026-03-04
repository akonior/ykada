use crate::error::{YkadaError, YkadaResult};

pub fn check_firmware_version(version: (u8, u8, u8)) -> YkadaResult<()> {
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
    fn test_accepts_5_7_0() {
        assert!(check_firmware_version((5, 7, 0)).is_ok());
    }

    #[test]
    fn test_accepts_5_7_4() {
        assert!(check_firmware_version((5, 7, 4)).is_ok());
    }

    #[test]
    fn test_accepts_newer_major() {
        assert!(check_firmware_version((6, 0, 0)).is_ok());
    }

    #[test]
    fn test_rejects_5_6_x() {
        let err = check_firmware_version((5, 6, 9)).unwrap_err();
        assert!(matches!(
            err,
            YkadaError::FirmwareIncompatible { found: (5, 6, 9) }
        ));
    }

    #[test]
    fn test_rejects_5_4_3() {
        assert!(matches!(
            check_firmware_version((5, 4, 3)).unwrap_err(),
            YkadaError::FirmwareIncompatible { .. }
        ));
    }
}
