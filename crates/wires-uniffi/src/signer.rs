//! `SwiftRootSigner` is the UniFFI callback trait the iOS app implements;
//! `SwiftRootSignerAdapter` bridges it to `wires_core::RootSigner` so the
//! rest of the crate can sign with plain `&dyn RootSigner` calls.

use std::sync::Arc;

use wires_core::{RootSigner, SignError, signer::RejectedSnafu};

use crate::error::WiresError;

#[uniffi::export(with_foreign)]
pub trait SwiftRootSigner: Send + Sync {
    fn pubkey(&self) -> Vec<u8>;
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WiresError>;
}

pub struct SwiftRootSignerAdapter {
    pub inner: Arc<dyn SwiftRootSigner>,
}

impl RootSigner for SwiftRootSignerAdapter {
    fn pubkey(&self) -> [u8; 32] {
        let v = self.inner.pubkey();
        let mut out = [0u8; 32];
        let n = v.len().min(32);
        out[..n].copy_from_slice(&v[..n]);
        out
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        let sig = self.inner.sign(message.to_vec()).map_err(|e| {
            RejectedSnafu {
                message: format!("{e}"),
            }
            .build()
        })?;
        if sig.len() != 64 {
            return Err(RejectedSnafu {
                message: format!("signer returned {} bytes, expected 64", sig.len()),
            }
            .build());
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use wires_core::Capability;

    struct FakeSwiftSigner(SigningKey);

    impl SwiftRootSigner for FakeSwiftSigner {
        fn pubkey(&self) -> Vec<u8> {
            self.0.verifying_key().to_bytes().to_vec()
        }
        fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WiresError> {
            let sig: ed25519_dalek::Signature = Signer::sign(&self.0, &message);
            Ok(sig.to_bytes().to_vec())
        }
    }

    #[test]
    fn adapter_signs_through_fake_swift_and_cap_verifies() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let swift: Arc<dyn SwiftRootSigner> = Arc::new(FakeSwiftSigner(sk));
        let adapter = SwiftRootSignerAdapter { inner: swift };
        assert_eq!(<SwiftRootSignerAdapter as RootSigner>::pubkey(&adapter), pk);

        let mut cap = Capability::new_unsigned(
            [7u8; 32],
            vec!["home.notes".into()],
            vec![wires_core::cap::Right::Read],
            1_700_000_000_000,
            None,
        );
        cap.sign(&adapter).unwrap();
        cap.verify(&pk).unwrap();
    }
}
