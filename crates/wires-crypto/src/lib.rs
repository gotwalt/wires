pub mod error;
pub mod public;
pub mod sealed;
pub mod standard;

pub use error::{CryptoError, Result};
pub use public::{decode_public, encode_public};
pub use sealed::{open_sealed, seal_to, sealed_nonce};
pub use standard::{EpochKey, decrypt_standard, encrypt_standard, standard_nonce};

// Re-export x25519_dalek types so downstream crates don't all need the dep.
pub use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

pub mod keywrap;
pub use keywrap::{unwrap_epoch_key, wrap_epoch_key};
