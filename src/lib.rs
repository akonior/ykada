// #![warn(clippy::must_use_candidate)]

mod adapters;
pub mod api;
pub mod error;
mod logic;
mod model;
pub mod ports;
pub mod use_cases;

pub use api::*;
pub use error::{YkadaError, YkadaResult};
