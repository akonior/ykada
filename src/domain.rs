//! Domain types for YubiKey operations
//!
//! This module defines domain-specific types that wrap primitives to:
//! - Prevent primitive obsession
//! - Enforce invariants at construction
//! - Provide type safety

mod algorithm;
mod mgmt_key;
mod ops;
mod pin;
mod policy;
mod slot;

pub use algorithm::{Algorithm, AlgorithmError};
pub use mgmt_key::{ManagementKey, ManagementKeyError};
pub use ops::{
    DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer, YubiKeyOps,
};
pub use pin::{Pin, PinError};
pub use policy::{PinPolicy, PolicyError, TouchPolicy};
pub use slot::{Slot, SlotError};
