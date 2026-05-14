use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use snafu::OptionExt;

use crate::error::{DecryptSnafu, EncryptSnafu, Result};

pub type EpochKey = [u8; 32];

/// 12-byte nonce derived deterministically from `BLAKE3(topic_id || sender || seq.to_le_bytes())[..12]`.
/// Unique per `(topic_id, sender, seq)` triple, which is enforced by the protocol's per-publisher
/// monotonic `seq`.
pub fn standard_nonce(topic_id: &[u8; 32], sender: &[u8; 32], seq: u64) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(topic_id);
    hasher.update(sender);
    hasher.update(&seq.to_le_bytes());
    let out = hasher.finalize();
    let bytes = out.as_bytes();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[..12]);
    nonce
}

/// Encrypt `content` under the topic's epoch key. The `aad` MUST equal the
/// cleartext envelope bytes; the caller assembles ciphertext into the envelope
/// and re-signs.
pub fn encrypt_standard(
    epoch_key: &EpochKey,
    topic_id: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    content: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
    let nonce_bytes = standard_nonce(topic_id, sender, seq);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(nonce, Payload { msg: content, aad })
        .ok()
        .context(EncryptSnafu)
}

pub fn decrypt_standard(
    epoch_key: &EpochKey,
    topic_id: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
    let nonce_bytes = standard_nonce(topic_id, sender, seq);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .context(DecryptSnafu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_deterministic_and_distinct_per_seq() {
        let topic = [1u8; 32];
        let sender = [2u8; 32];
        let a = standard_nonce(&topic, &sender, 0);
        let b = standard_nonce(&topic, &sender, 1);
        let a2 = standard_nonce(&topic, &sender, 0);
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_changes_with_topic_id() {
        let sender = [2u8; 32];
        let a = standard_nonce(&[1u8; 32], &sender, 7);
        let b = standard_nonce(&[2u8; 32], &sender, 7);
        assert_ne!(a, b);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [9u8; 32];
        let topic = [1u8; 32];
        let sender = [2u8; 32];
        let aad = b"envelope-aad";
        let ct = encrypt_standard(&key, &topic, &sender, 7, b"hello", aad).unwrap();
        let pt = decrypt_standard(&key, &topic, &sender, 7, &ct, aad).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn aad_mismatch_fails() {
        let key = [9u8; 32];
        let ct = encrypt_standard(&key, &[1u8; 32], &[2u8; 32], 7, b"x", b"a").unwrap();
        assert!(decrypt_standard(&key, &[1u8; 32], &[2u8; 32], 7, &ct, b"b").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt_standard(&[1u8; 32], &[1u8; 32], &[2u8; 32], 7, b"x", b"a").unwrap();
        assert!(decrypt_standard(&[2u8; 32], &[1u8; 32], &[2u8; 32], 7, &ct, b"a").is_err());
    }

    #[test]
    fn wrong_seq_fails_decrypt() {
        let key = [9u8; 32];
        let ct = encrypt_standard(&key, &[1u8; 32], &[2u8; 32], 7, b"x", b"a").unwrap();
        assert!(decrypt_standard(&key, &[1u8; 32], &[2u8; 32], 8, &ct, b"a").is_err());
    }
}
