uniffi::setup_scaffolding!();

pub mod error;
pub mod signer;
pub mod types;
pub use error::{WiresError, WiresResult};
pub use signer::{SwiftRootSigner, SwiftRootSignerAdapter};
pub use types::*;
