//! Use cases (orchestration)
//!
//! This module contains use cases that orchestrate operations across multiple ports.
//! Use cases coordinate between adapters and logic to fulfill business requirements.

mod generate_key;

pub use generate_key::generate_key;
