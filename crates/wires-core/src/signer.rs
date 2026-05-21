//! `RootSigner` — the fabric's root-of-trust signing abstraction. Implemented
//! by an in-process `SigningKey` for CLI/daemon use and by a callback-backed
//! adapter from `wires-uniffi` for iOS Keychain biometric signing.

use ed25519_dalek::SigningKey;
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum SignError {
    #[snafu(display("Root signer rejected the message: {message}, at {location}"))]
    Rejected {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub trait RootSigner: Send + Sync {
    fn pubkey(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError>;
}

impl RootSigner for SigningKey {
    fn pubkey(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        let sig: ed25519_dalek::Signature = ed25519_dalek::Signer::sign(self, message);
        Ok(sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn signing_key_impl_signs_and_pubkey_matches() {
        let sk = SigningKey::generate(&mut OsRng);
        assert_eq!(
            <SigningKey as RootSigner>::pubkey(&sk),
            sk.verifying_key().to_bytes()
        );
        let sig = <SigningKey as RootSigner>::sign(&sk, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn dyn_dispatch_compiles() {
        let sk = SigningKey::generate(&mut OsRng);
        let root: &dyn RootSigner = &sk;
        let _ = root.sign(b"x").unwrap();
        let _ = root.pubkey();
    }
}
