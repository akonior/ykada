//! Domain types for YubiKey operations
//!
//! This module defines domain-specific types that wrap primitives to:
//! - Prevent primitive obsession
//! - Enforce invariants at construction
//! - Provide type safety

mod algorithm;
mod pin;
mod policy;
mod slot;

pub use algorithm::{Algorithm, AlgorithmError};
pub use pin::{Pin, PinError};
pub use policy::{PinPolicy, PolicyError, TouchPolicy};
pub use slot::{Slot, SlotError};
