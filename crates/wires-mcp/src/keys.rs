//! Token signing key: a single ed25519 keypair persisted in
//! `<data_dir>/token_signing.ed25519` (raw 32 bytes, mode 0600). Used by
//! `token::mint` to sign JWTs and exposed via `/.well-known/jwks.json`.

use std::path::Path;

use ed25519_dalek::SigningKey;
use snafu::ResultExt;

use crate::error::{IoSnafu, Result};

/// The `kid` advertised in JWKS and embedded in every minted JWT. Stable
/// across process restarts because it's derived from the public key.
pub fn kid_for(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    let bytes = verifying_key.to_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"wires-mcp.token-kid.v1");
    hasher.update(&bytes);
    let h = hasher.finalize();
    hex::encode(&h.as_bytes()[..8])
}

/// Load the signing key from `path`, or generate one if absent. The on-disk
/// representation is raw 32 bytes; mode 0600 on creation.
pub fn load_or_create(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let bytes = std::fs::read(path).context(IoSnafu)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::error::GatewayError::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "token_signing.ed25519 must be exactly 32 bytes",
                ),
                location: snafu::location!(),
            })?;
        return Ok(SigningKey::from_bytes(&arr));
    }
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context(IoSnafu)?;
    }
    write_secret(path, sk.to_bytes().as_slice())?;
    Ok(sk)
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .context(IoSnafu)?;
    f.write_all(bytes).context(IoSnafu)?;
    f.sync_all().context(IoSnafu)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).context(IoSnafu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generates_a_key_when_missing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("token_signing.ed25519");
        assert!(!path.exists());
        let sk = load_or_create(&path).unwrap();
        assert!(path.exists());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes.as_slice(), sk.to_bytes().as_slice());
    }

    #[test]
    fn loads_existing_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("token_signing.ed25519");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn kid_is_stable() {
        let sk1 = SigningKey::from_bytes(&[7u8; 32]);
        let sk2 = SigningKey::from_bytes(&[7u8; 32]);
        assert_eq!(kid_for(&sk1.verifying_key()), kid_for(&sk2.verifying_key()));
        let sk3 = SigningKey::from_bytes(&[8u8; 32]);
        assert_ne!(kid_for(&sk1.verifying_key()), kid_for(&sk3.verifying_key()));
    }
}
