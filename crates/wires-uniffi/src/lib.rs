uniffi::setup_scaffolding!();

pub mod app;
pub mod error;
pub mod pair;
pub mod parse;
pub mod signer;
pub mod fabric;
pub mod ticket;
pub mod topic;
pub mod types;
pub use app::WiresApp;
pub use error::{WiresError, WiresResult};
pub use signer::{SwiftRootSigner, SwiftRootSignerAdapter};
pub use types::*;
