//! YubiKey implementations module (legacy re-exports)
//!
//! This module re-exports adapters from the new structure for backward compatibility.
//! New code should use `crate::adapters` directly.

// Re-export adapters
pub use crate::adapters::{PivDeviceFinder, PivYubiKey};
