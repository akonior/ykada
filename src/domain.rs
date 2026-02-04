//! Domain types for YubiKey operations (legacy re-exports)
//!
//! This module re-exports types from the new structure for backward compatibility.
//! New code should use `crate::model` and `crate::ports` directly.

// Re-export model types
pub use crate::model::{
    Algorithm, AlgorithmError, ManagementKey, ManagementKeyError, Pin, PinError, PinPolicy,
    PolicyError, Slot, SlotError, TouchPolicy,
};

// Re-export port types
pub use crate::ports::{
    DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer, YubiKeyOps,
};

// Keep ops module for tests that reference it
mod ops;
