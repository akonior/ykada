/*!
YubiKey operations module

This module defines trait algebras (interfaces) for YubiKey operations
and provides concrete implementations. The traits allow dependency injection
and make the code testable without requiring actual hardware.
*/

//! YubiKey implementations module
//!
//! This module provides concrete implementations of YubiKey operation traits.
//! Currently supports PIV (Personal Identity Verification) implementation.
//! Future implementations may include OpenPGP support.
//!
//! Trait definitions (algebras) are in `crate::domain::ops`.

mod piv;

pub use piv::{PivDeviceFinder, PivYubiKey};
