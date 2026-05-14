use std::path::Path;

use rand_core::{OsRng, RngCore};
use snafu::ResultExt;

use crate::error::{IoSnafu, Result};

/// Load or create a 32-byte secret stored at `path`. Used for both the
/// wires-level Ed25519 keypair and the iroh node secret.
pub fn load_or_create_secret(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        let bytes = std::fs::read(path).context(IoSnafu)?;
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
        // File exists but is the wrong size — treat as corrupt and regenerate.
        // (Production code might prefer to surface an error; v1 self-heals.)
    }
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context(IoSnafu)?;
    }
    std::fs::write(path, bytes).context(IoSnafu)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_then_reuses_secret() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("secret");
        let a = load_or_create_secret(&p).unwrap();
        let b = load_or_create_secret(&p).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn creates_parent_dir_if_missing() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("nested/sub/secret");
        let secret = load_or_create_secret(&p).unwrap();
        assert!(p.exists());
        // Reload via the same path
        let again = load_or_create_secret(&p).unwrap();
        assert_eq!(secret, again);
    }

    #[test]
    fn corrupt_file_regenerated() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("secret");
        std::fs::write(&p, &[1, 2, 3]).unwrap(); // wrong size
        let secret = load_or_create_secret(&p).unwrap();
        assert_eq!(secret.len(), 32);
        // Now it's a valid 32-byte secret on disk
        let again = load_or_create_secret(&p).unwrap();
        assert_eq!(secret, again);
    }
}
