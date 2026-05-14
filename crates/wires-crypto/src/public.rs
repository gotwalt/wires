//! Public mode: content is cleartext. Integrity comes from the envelope signature.
//! These helpers exist so callers don't have to special-case Public mode at every call site.

pub fn encode_public(content: &[u8]) -> Vec<u8> {
    content.to_vec()
}

pub fn decode_public(ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_is_identity() {
        let c = b"plaintext content";
        assert_eq!(encode_public(c), decode_public(&encode_public(c)));
    }
}
