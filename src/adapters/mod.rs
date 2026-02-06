//! Adapters - concrete implementations of ports (traits)

mod yubikey_piv;

#[cfg(test)]
pub mod fake_yubikey;

// Re-export for convenience
pub use yubikey_piv::PivDeviceFinder;
