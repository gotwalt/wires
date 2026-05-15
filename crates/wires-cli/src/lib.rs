//! Library half of `wires-cli`. Exists so integration tests can drive
//! subcommand handlers without running the binary through a subprocess.

pub mod cmd;
pub mod error;

pub use error::{CliError, Result};
