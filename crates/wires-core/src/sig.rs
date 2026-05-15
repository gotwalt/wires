use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use snafu::{OptionExt, ensure};

use crate::error::{BadSignatureSnafu, Result};
use crate::wire::WireMessage;

/// Sign an envelope in-place. Caller fills every field except `signature`,
/// then calls this; the function fills `signature`.
pub fn sign_envelope(msg: &mut WireMessage, sk: &SigningKey) -> Result<()> {
    let bytes = msg.signing_bytes()?;
    let sig = sk.sign(&bytes);
    msg.signature = sig.to_bytes();
    Ok(())
}

/// Verify the envelope's signature against the sender pubkey in the envelope.
pub fn verify_envelope(msg: &WireMessage) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&msg.sender)
        .ok()
        .context(BadSignatureSnafu)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.signature);
    let bytes = msg.signing_bytes()?;
    ensure!(vk.verify(&bytes, &sig).is_ok(), BadSignatureSnafu);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{MessageKind, Pubkey};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn fresh_msg(sender: Pubkey) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender,
            cap_id: [0u8; 16],
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp: 0,
            payload_len: 0,
            signature: [0u8; 64],
            ciphertext: vec![],
        }
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let mut msg = fresh_msg(pk);
        sign_envelope(&mut msg, &sk).unwrap();
        verify_envelope(&msg).unwrap();
    }

    #[test]
    fn tampered_envelope_fails_verify() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let mut msg = fresh_msg(pk);
        sign_envelope(&mut msg, &sk).unwrap();
        msg.seq = 1; // tamper after signing
        assert!(verify_envelope(&msg).is_err());
    }

    #[test]
    fn wrong_sender_fails_verify() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let mut msg = fresh_msg(sk_a.verifying_key().to_bytes());
        sign_envelope(&mut msg, &sk_b).unwrap();
        assert!(verify_envelope(&msg).is_err());
    }
}
