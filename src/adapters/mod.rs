//! Adapters - concrete implementations of ports (traits)

mod yubikey_piv;

#[cfg(test)]
pub mod mock_yubikey;

#[cfg(test)]
mod mock_yubikey_tests;

// Re-export for convenience
pub use yubikey_piv::{PivDeviceFinder, PivYubiKey};
