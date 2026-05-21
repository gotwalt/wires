//! `topic_names.json` — local name → topic_id (hex) map. Used by the CLI for
//! human-friendly topic references and by `install_grant` for merging pair-time
//! entries.

use std::collections::HashMap;
use std::path::Path;

use snafu::ResultExt;

use crate::atomic_write::atomic_write;
use crate::error::{NodeError, Result, TopicNamesWriteSnafu};

const FILE: &str = "topic_names.json";
const DM_ROSTER_FILE: &str = "dm_roster.json";

/// Resolve `topic` to a 32-byte id. Accepts either a 64-character hex id or a
/// human name listed in `<data_dir>/topic_names.json`. Returns an io error if
/// the name isn't a hex id and isn't in the file.
pub fn resolve_topic(data_dir: &Path, topic: &str) -> std::io::Result<[u8; 32]> {
    if let Ok(bytes) = hex::decode(topic)
        && let Ok(arr) = <[u8; 32]>::try_from(bytes)
    {
        return Ok(arr);
    }
    let map = read_map(data_dir)?;
    let hex_id = map.get(topic).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("unknown topic '{topic}'"),
        )
    })?;
    let bytes = hex::decode(hex_id).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("topic_names.json entry not hex: {e}"),
        )
    })?;
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "topic_names.json entry not 32 bytes",
        )
    })
}

/// Read `topic_names.json` into a `name -> 32-byte topic_id` map. Returns an
/// empty map if the file does not exist.
pub fn load_topic_names(data_dir: &Path) -> std::io::Result<HashMap<String, [u8; 32]>> {
    let raw = read_map(data_dir)?;
    let mut out = HashMap::with_capacity(raw.len());
    for (k, v) in raw {
        let bytes = hex::decode(&v).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("topic_names.json[{k}] not hex: {e}"),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("topic_names.json[{k}] not 32 bytes"),
            )
        })?;
        out.insert(k, arr);
    }
    Ok(out)
}

fn read_map(data_dir: &Path) -> std::io::Result<HashMap<String, String>> {
    let p = data_dir.join(FILE);
    if !p.exists() {
        return Ok(HashMap::new());
    }
    let s = std::fs::read_to_string(&p)?;
    serde_json::from_str(&s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Merge `(name, topic_id)` entries into `<data_dir>/topic_names.json`,
/// preserving any existing entries.
pub fn upsert_entries<I: IntoIterator<Item = (String, [u8; 32])>>(
    data_dir: &Path,
    entries: I,
) -> Result<()> {
    let p = data_dir.join(FILE);
    let mut map: HashMap<String, String> = if p.exists() {
        let s = std::fs::read_to_string(&p).context(TopicNamesWriteSnafu)?;
        serde_json::from_str(&s).map_err(|e| NodeError::TopicNamesWrite {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            location: snafu::location!(),
        })?
    } else {
        HashMap::new()
    };
    for (name, id) in entries {
        map.insert(name, hex::encode(id));
    }
    let serialized = serde_json::to_string_pretty(&map).expect("HashMap serializes");
    atomic_write(&p, serialized.as_bytes(), None).context(TopicNamesWriteSnafu)?;
    Ok(())
}

/// Merge `(agent_ed25519_hex, agent_x25519_hex)` entries into
/// `<data_dir>/dm_roster.json`. The file is a flat `HashMap<String, String>` —
/// later entries overwrite earlier ones for the same key.
///
/// Mode bits are not strictly enforced here; the file may contain household
/// secrets indirectly via the x25519 pubkey of trusted peers, but the
/// pubkey itself is not secret. We rely on the data_dir's 0700 directory
/// mode for confidentiality (same as `identity.*`).
pub fn upsert_dm_roster<'a, I: IntoIterator<Item = (&'a str, &'a str)>>(
    data_dir: &Path,
    entries: I,
) -> Result<()> {
    let p = data_dir.join(DM_ROSTER_FILE);
    let mut map: HashMap<String, String> = if p.exists() {
        let s = std::fs::read_to_string(&p).context(TopicNamesWriteSnafu)?;
        serde_json::from_str(&s).map_err(|e| NodeError::TopicNamesWrite {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            location: snafu::location!(),
        })?
    } else {
        HashMap::new()
    };
    for (ed_hex, x_hex) in entries {
        map.insert(ed_hex.to_string(), x_hex.to_string());
    }
    let serialized = serde_json::to_string_pretty(&map).expect("HashMap serializes");
    atomic_write(&p, serialized.as_bytes(), None).context(TopicNamesWriteSnafu)?;
    Ok(())
}

/// Read `dm_roster.json` into a `agent_ed25519_hex -> agent_x25519_hex` map.
/// Returns an empty map if the file does not exist.
pub fn load_dm_roster(data_dir: &Path) -> std::io::Result<HashMap<String, String>> {
    let p = data_dir.join(DM_ROSTER_FILE);
    if !p.exists() {
        return Ok(HashMap::new());
    }
    let s = std::fs::read_to_string(&p)?;
    serde_json::from_str(&s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}
