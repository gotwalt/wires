use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum CryptoError {
    #[snafu(display("Core error during crypto operation, at {location}"))]
    Core {
        #[snafu(source)]
        source: wires_core::CoreError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("AEAD encryption failed, at {location}"))]
    Encrypt {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("AEAD decryption failed (tag mismatch or corrupted ciphertext), at {location}"))]
    Decrypt {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Sealed-box ciphertext too short to contain ephemeral pubkey, at {location}"))]
    SealedShort {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Invalid x25519 key, at {location}"))]
    BadX25519Key {
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T, E = CryptoError> = core::result::Result<T, E>;
