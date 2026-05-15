//! On-wire frames exchanged over `/wires/pair/0`.

use serde::{Deserialize, Serialize};

use super::grant::PairGrantEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairFrame {
    Grant(PairGrantEnvelope),
    Ack(PairAck),
    Reject(PairReject),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairAck {
    #[serde(with = "hex::serde")]
    pub installed_cap_id: [u8; 16],
    pub installed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairReject {
    pub code: PairRejectCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairRejectCode {
    NonceMismatch,
    NonceExpired,
    SignatureInvalid,
    SealUndecryptable,
    RootMismatch,
    CapInvalid,
    UnknownTopic,
    AlreadyPaired,
    InternalError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_frame_roundtrip() {
        let env = PairGrantEnvelope {
            root_pubkey: [1u8; 32],
            sealed_payload: vec![0x10, 0x11, 0x12],
            signature: [2u8; 64],
        };
        let f = PairFrame::Grant(env);
        let j = serde_json::to_vec(&f).unwrap();
        let back: PairFrame = serde_json::from_slice(&j).unwrap();
        match back {
            PairFrame::Grant(e) => assert_eq!(e.sealed_payload, vec![0x10, 0x11, 0x12]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ack_frame_roundtrip() {
        let f = PairFrame::Ack(PairAck {
            installed_cap_id: [9u8; 16],
            installed_at: 42,
        });
        let j = serde_json::to_vec(&f).unwrap();
        let back: PairFrame = serde_json::from_slice(&j).unwrap();
        assert!(matches!(back, PairFrame::Ack(_)));
    }

    #[test]
    fn reject_frame_carries_code_and_message() {
        let f = PairFrame::Reject(PairReject {
            code: PairRejectCode::NonceMismatch,
            message: "nonce".into(),
        });
        let j = serde_json::to_vec(&f).unwrap();
        let back: PairFrame = serde_json::from_slice(&j).unwrap();
        match back {
            PairFrame::Reject(r) => {
                assert_eq!(r.code, PairRejectCode::NonceMismatch);
                assert_eq!(r.message, "nonce");
            }
            _ => panic!("wrong variant"),
        }
    }
}
