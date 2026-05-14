pub mod error;
pub mod gossip;
pub mod identity;

pub use error::{NetError, Result};
pub use gossip::{GossipHandle, GossipNode};
pub use identity::load_or_create_secret;
