pub mod error;
pub mod identity;

pub use error::{NetError, Result};
pub use identity::load_or_create_secret;
