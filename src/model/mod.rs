//! Domain model entities
//!
//! This module contains domain entities (value objects, domain types).
//! These are pure data structures with validation logic.

mod algorithm;
mod key_material;
mod mgmt_key;
mod pin;
mod policy;
mod slot;

pub use algorithm::{Algorithm, AlgorithmError};
pub use key_material::{DerPrivateKey, KeyMaterialError, KeyPair, PrivateKey, PublicKey};
pub use mgmt_key::{ManagementKey, ManagementKeyError};
pub use pin::{Pin, PinError};
pub use policy::{PinPolicy, PolicyError, TouchPolicy};
pub use slot::{Slot, SlotError};
