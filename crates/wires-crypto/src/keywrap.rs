use snafu::location;
use x25519_dalek::StaticSecret;

use crate::error::{CryptoError, Result};
use crate::sealed::{open_sealed, seal_to};

pub type EpochKey = [u8; 32];

/// Wrap an epoch key for delivery to `recipient_pk`. The result is the
/// `ciphertext` field for a `MessageKind::SealedTo` envelope.
pub fn wrap_epoch_key(
    recipient_pk: &[u8; 32],
    topic_id: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    key: &EpochKey,
    aad: &[u8],
) -> Result<Vec<u8>> {
    seal_to(recipient_pk, topic_id, sender, seq, key, aad)
}

pub fn unwrap_epoch_key(
    recipient_sk: &StaticSecret,
    topic_id: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    sealed: &[u8],
    aad: &[u8],
) -> Result<EpochKey> {
    let bytes = open_sealed(recipient_sk, topic_id, sender, seq, sealed, aad)?;
    let arr: EpochKey = bytes.try_into().map_err(|_| CryptoError::Decrypt {
        location: location!(),
    })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn wrap_unwrap_roundtrip() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        let epoch_key: EpochKey = [42u8; 32];
        let sealed = wrap_epoch_key(&pk, &[1u8; 32], &[2u8; 32], 0, &epoch_key, b"aad").unwrap();
        let back = unwrap_epoch_key(&sk, &[1u8; 32], &[2u8; 32], 0, &sealed, b"aad").unwrap();
        assert_eq!(back, epoch_key);
    }

    #[test]
    fn unwrap_with_wrong_recipient_fails() {
        let sk_a = StaticSecret::random_from_rng(OsRng);
        let pk_a = PublicKey::from(&sk_a).to_bytes();
        let sk_b = StaticSecret::random_from_rng(OsRng);
        let sealed = wrap_epoch_key(&pk_a, &[1u8; 32], &[2u8; 32], 0, &[7u8; 32], b"aad").unwrap();
        assert!(unwrap_epoch_key(&sk_b, &[1u8; 32], &[2u8; 32], 0, &sealed, b"aad").is_err());
    }

    #[test]
    fn unwrap_with_wrong_aad_fails() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        let sealed = wrap_epoch_key(&pk, &[1u8; 32], &[2u8; 32], 0, &[7u8; 32], b"a").unwrap();
        assert!(unwrap_epoch_key(&sk, &[1u8; 32], &[2u8; 32], 0, &sealed, b"b").is_err());
    }
}
