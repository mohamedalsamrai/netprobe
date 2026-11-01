//! Shared pieces of netprobe: configuration, the measurement data model and the formulas.

pub mod config;
pub mod model;
pub mod stats;

pub use config::Config;
pub use model::Record;
