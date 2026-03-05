// #![warn(clippy::must_use_candidate)]

mod adapters;
pub mod api;
mod error;
mod logic;
mod model;
mod ports;
mod use_cases;

pub use api::*;
pub use error::{YkadaError, YkadaResult};
