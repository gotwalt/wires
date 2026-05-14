use serde::{Deserialize, Serialize};

pub type Pubkey = [u8; 32];
pub type TopicId = [u8; 32];
pub type CapId = [u8; 16];
pub type Signature = [u8; 64];
pub type MessageHash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "to", rename_all = "snake_case")]
pub enum MessageKind {
    Standard,
    SealedTo(#[serde(with = "hex::serde")] Pubkey),
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    #[serde(with = "hex::serde")]
    pub topic_id: TopicId,
    pub epoch: u32,
    pub kind: MessageKind,
    #[serde(with = "hex::serde")]
    pub sender: Pubkey,
    #[serde(with = "hex::serde")]
    pub cap_id: CapId,
    pub seq: u64,
    #[serde(with = "hex::serde")]
    pub prev_hash: MessageHash,
    pub timestamp: i64,
    pub payload_len: u32,
    #[serde(with = "hex::serde")]
    pub signature: Signature,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl WireMessage {
    /// Bytes used both as AEAD AAD and as input to the signature: every
    /// envelope field above `signature`, in canonical JSON order. Stable
    /// across re-serialization.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, crate::error::CoreError> {
        use snafu::ResultExt;
        #[derive(Serialize)]
        struct SigningView<'a> {
            #[serde(with = "hex::serde")]
            topic_id: &'a TopicId,
            epoch: u32,
            kind: &'a MessageKind,
            #[serde(with = "hex::serde")]
            sender: &'a Pubkey,
            #[serde(with = "hex::serde")]
            cap_id: &'a CapId,
            seq: u64,
            #[serde(with = "hex::serde")]
            prev_hash: &'a MessageHash,
            timestamp: i64,
            payload_len: u32,
            #[serde(with = "serde_bytes")]
            ciphertext: &'a [u8],
        }
        let view = SigningView {
            topic_id: &self.topic_id,
            epoch: self.epoch,
            kind: &self.kind,
            sender: &self.sender,
            cap_id: &self.cap_id,
            seq: self.seq,
            prev_hash: &self.prev_hash,
            timestamp: self.timestamp,
            payload_len: self.payload_len,
            ciphertext: &self.ciphertext,
        };
        serde_json::to_vec(&view).context(crate::error::SerializeEnvelopeSnafu)
    }

    /// Identity of a message in storage and in hash-chain links.
    pub fn message_hash(&self) -> Result<MessageHash, crate::error::CoreError> {
        let bytes = self.signing_bytes()?;
        let hash = blake3::hash(&bytes);
        Ok(*hash.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 7,
            kind: MessageKind::Standard,
            sender: [2u8; 32],
            cap_id: [3u8; 16],
            seq: 42,
            prev_hash: [4u8; 32],
            timestamp: 1_700_000_000_000,
            payload_len: 9,
            signature: [5u8; 64],
            ciphertext: vec![9, 8, 7, 6, 5, 4, 3, 2, 1],
        }
    }

    #[test]
    fn signing_bytes_excludes_signature() {
        let a = sample();
        let mut b = sample();
        b.signature = [0xFFu8; 64];
        assert_eq!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap());
    }

    #[test]
    fn signing_bytes_includes_ciphertext() {
        let a = sample();
        let mut b = sample();
        b.ciphertext[0] ^= 1;
        assert_ne!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap());
    }

    #[test]
    fn message_hash_is_stable_across_serialization() {
        let a = sample();
        let bytes = serde_json::to_vec(&a).unwrap();
        let b: WireMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(a.message_hash().unwrap(), b.message_hash().unwrap());
    }

    #[test]
    fn message_kind_round_trips_through_json() {
        for k in [
            MessageKind::Standard,
            MessageKind::SealedTo([0xAAu8; 32]),
            MessageKind::Public,
        ] {
            let s = serde_json::to_string(&k).unwrap();
            let r: MessageKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, r);
        }
    }

    /// Safety net for the `SigningView` mirror in `signing_bytes()`: if a new
    /// field is added to `WireMessage` and forgotten in `SigningView`, signing
    /// bytes will silently omit it — breaking the security model. This test
    /// mutates every non-signature field and asserts each mutation changes
    /// `signing_bytes()`. Add a case here whenever you add a field.
    #[test]
    fn signing_bytes_covers_every_non_signature_field() {
        let base = sample();
        let base_bytes = base.signing_bytes().unwrap();

        let mut m = sample(); m.topic_id[0] ^= 1;
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "topic_id not in signing_bytes");

        let mut m = sample(); m.epoch = base.epoch.wrapping_add(1);
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "epoch not in signing_bytes");

        let mut m = sample(); m.kind = MessageKind::Public;
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "kind not in signing_bytes");

        let mut m = sample(); m.sender[0] ^= 1;
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "sender not in signing_bytes");

        let mut m = sample(); m.cap_id[0] ^= 1;
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "cap_id not in signing_bytes");

        let mut m = sample(); m.seq = base.seq.wrapping_add(1);
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "seq not in signing_bytes");

        let mut m = sample(); m.prev_hash[0] ^= 1;
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "prev_hash not in signing_bytes");

        let mut m = sample(); m.timestamp = base.timestamp.wrapping_add(1);
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "timestamp not in signing_bytes");

        let mut m = sample(); m.payload_len = base.payload_len.wrapping_add(1);
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "payload_len not in signing_bytes");

        let mut m = sample(); m.ciphertext[0] ^= 1;
        assert_ne!(base_bytes, m.signing_bytes().unwrap(), "ciphertext not in signing_bytes");
    }
}
