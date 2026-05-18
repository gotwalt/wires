//! redb-backed gateway state. One file at `<data_dir>/gateway.redb`. Every
//! table is keyed by a stable identifier (root_pubkey_hex, client_id,
//! session_id, etc.) and stores a JSON-serialized record value. The shape of
//! each record is in this module; the design rationale is in the spec.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::{JsonSnafu, RedbOpenSnafu, RedbSnafu, Result};

const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
const OAUTH_CLIENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("oauth_clients");
const AUTH_SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_sessions");
const PENDING_PAIRS: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_pairs");
const PENDING_SIGNINS: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_signins");
const AUTH_CODES: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_codes");
const REFRESH_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("refresh_tokens");
const REVOKED_JTIS: TableDefinition<&str, &[u8]> = TableDefinition::new("revoked_jtis");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub root_pubkey_hex: String,
    pub data_dir: String,
    pub created_at_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OauthClientRecord {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub created_at_ms: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthSessionKind {
    Pending,
    Done { auth_code: String, sub: String },
    Expired,
    Failed { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSessionRecord {
    pub session_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub resource: String,
    pub state: String,
    pub kind: AuthSessionKind,
    pub issued_at_ms: i64,
    pub expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPairRecord {
    pub session_id: String,
    pub temp_data_dir: String,
    pub request_token_b64: String,
    pub ttl_expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingSigninRecord {
    pub session_id: String,
    pub challenge_nonce_hex: String,
    pub ttl_expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthCodeRecord {
    pub code: String,
    pub session_id: String,
    pub sub: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub issued_at_ms: i64,
    pub expires_ms: i64,
    pub consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    pub token_hash_hex: String,
    pub sub: String,
    pub client_id: String,
    pub issued_at_ms: i64,
    pub expires_ms: i64,
    pub rotated_to_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedJtiRecord {
    pub jti: String,
    pub revoked_at_ms: i64,
}

#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| crate::error::GatewayError::Io {
                source: e,
                location: snafu::location!(),
            })?;
        }
        let db = Database::create(path).context(RedbOpenSnafu)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn put_user(&self, rec: &UserRecord) -> Result<()> {
        let bytes = serde_json::to_vec(rec).context(JsonSnafu)?;
        let write = self.db.begin_write().map_err(|e| e.into()).context(RedbSnafu)?;
        {
            let mut t = write.open_table(USERS).map_err(|e| e.into()).context(RedbSnafu)?;
            t.insert(rec.root_pubkey_hex.as_str(), bytes.as_slice())
                .map_err(|e| e.into()).context(RedbSnafu)?;
        }
        write.commit().map_err(|e| e.into()).context(RedbSnafu)
    }

    pub fn get_user(&self, root_pubkey_hex: &str) -> Result<Option<UserRecord>> {
        let read = self.db.begin_read().map_err(|e| e.into()).context(RedbSnafu)?;
        let t = match read.open_table(USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        let v = match t.get(root_pubkey_hex).map_err(|e| e.into()).context(RedbSnafu)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let rec: UserRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
        Ok(Some(rec))
    }

    pub fn list_users(&self) -> Result<Vec<UserRecord>> {
        let read = self.db.begin_read().map_err(|e| e.into()).context(RedbSnafu)?;
        let t = match read.open_table(USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        let mut out = Vec::new();
        for r in t.iter().map_err(|e| e.into()).context(RedbSnafu)? {
            let (_, v) = r.map_err(|e| e.into()).context(RedbSnafu)?;
            let rec: UserRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
            out.push(rec);
        }
        Ok(out)
    }

    pub fn delete_user(&self, root_pubkey_hex: &str) -> Result<bool> {
        let write = self.db.begin_write().map_err(|e| e.into()).context(RedbSnafu)?;
        let existed;
        {
            let mut t = write.open_table(USERS).map_err(|e| e.into()).context(RedbSnafu)?;
            existed = t.remove(root_pubkey_hex).map_err(|e| e.into()).context(RedbSnafu)?.is_some();
        }
        write.commit().map_err(|e| e.into()).context(RedbSnafu)?;
        Ok(existed)
    }
}

// Generic JSON record helpers. Each table gets a thin accessor pair.

macro_rules! json_record_accessors {
    ($put:ident, $get:ident, $delete:ident, $table:expr, $rec:ty, $key_field:ident) => {
        impl Store {
            pub fn $put(&self, rec: &$rec) -> Result<()> {
                let bytes = serde_json::to_vec(rec).context(JsonSnafu)?;
                let write = self.db.begin_write().map_err(|e| e.into()).context(RedbSnafu)?;
                {
                    let mut t = write.open_table($table).map_err(|e| e.into()).context(RedbSnafu)?;
                    t.insert(rec.$key_field.as_str(), bytes.as_slice())
                        .map_err(|e| e.into()).context(RedbSnafu)?;
                }
                write.commit().map_err(|e| e.into()).context(RedbSnafu)
            }
            pub fn $get(&self, key: &str) -> Result<Option<$rec>> {
                let read = self.db.begin_read().map_err(|e| e.into()).context(RedbSnafu)?;
                let t = match read.open_table($table) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                    Err(e) => return Err(crate::error::GatewayError::Redb {
                        source: e.into(),
                        location: snafu::location!(),
                    }),
                };
                let v = match t.get(key).map_err(|e| e.into()).context(RedbSnafu)? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                let rec: $rec = serde_json::from_slice(v.value()).context(JsonSnafu)?;
                Ok(Some(rec))
            }
            pub fn $delete(&self, key: &str) -> Result<bool> {
                let write = self.db.begin_write().map_err(|e| e.into()).context(RedbSnafu)?;
                let existed;
                {
                    let mut t = write.open_table($table).map_err(|e| e.into()).context(RedbSnafu)?;
                    existed = t.remove(key).map_err(|e| e.into()).context(RedbSnafu)?.is_some();
                }
                write.commit().map_err(|e| e.into()).context(RedbSnafu)?;
                Ok(existed)
            }
        }
    };
}

json_record_accessors!(put_oauth_client, get_oauth_client, delete_oauth_client, OAUTH_CLIENTS, OauthClientRecord, client_id);
json_record_accessors!(put_auth_session, get_auth_session, delete_auth_session, AUTH_SESSIONS, AuthSessionRecord, session_id);
json_record_accessors!(put_pending_pair, get_pending_pair, delete_pending_pair, PENDING_PAIRS, PendingPairRecord, session_id);
json_record_accessors!(put_pending_signin, get_pending_signin, delete_pending_signin, PENDING_SIGNINS, PendingSigninRecord, session_id);
json_record_accessors!(put_auth_code, get_auth_code, delete_auth_code, AUTH_CODES, AuthCodeRecord, code);
json_record_accessors!(put_refresh_token, get_refresh_token, delete_refresh_token, REFRESH_TOKENS, RefreshTokenRecord, token_hash_hex);
json_record_accessors!(put_revoked_jti, get_revoked_jti, delete_revoked_jti, REVOKED_JTIS, RevokedJtiRecord, jti);

impl Store {
    pub fn list_oauth_clients(&self) -> Result<Vec<OauthClientRecord>> {
        let read = self.db.begin_read().map_err(|e| e.into()).context(RedbSnafu)?;
        let t = match read.open_table(OAUTH_CLIENTS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        let mut out = Vec::new();
        for r in t.iter().map_err(|e| e.into()).context(RedbSnafu)? {
            let (_, v) = r.map_err(|e| e.into()).context(RedbSnafu)?;
            let rec: OauthClientRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
            out.push(rec);
        }
        Ok(out)
    }

    pub fn revoke_refresh_tokens_for_sub(&self, sub: &str) -> Result<usize> {
        let read = self.db.begin_read().map_err(|e| e.into()).context(RedbSnafu)?;
        let hashes: Vec<String> = match read.open_table(REFRESH_TOKENS) {
            Ok(t) => {
                let mut keys = Vec::new();
                for r in t.iter().map_err(|e| e.into()).context(RedbSnafu)? {
                    let (_, v) = r.map_err(|e| e.into()).context(RedbSnafu)?;
                    let rec: RefreshTokenRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
                    if rec.sub == sub {
                        keys.push(rec.token_hash_hex);
                    }
                }
                keys
            }
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        drop(read);
        let mut n = 0;
        for h in &hashes {
            if self.delete_refresh_token(h)? {
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn s() -> (TempDir, Store) {
        let tmp = TempDir::new().unwrap();
        let store = Store::open(&tmp.path().join("gateway.redb")).unwrap();
        (tmp, store)
    }

    #[test]
    fn users_put_get_list_delete_roundtrip() {
        let (_t, store) = s();
        let r = UserRecord {
            root_pubkey_hex: "ab".repeat(32),
            data_dir: "/tmp/x".into(),
            created_at_ms: 1,
            last_seen_ms: 2,
        };
        store.put_user(&r).unwrap();
        assert_eq!(store.get_user(&r.root_pubkey_hex).unwrap(), Some(r.clone()));
        assert_eq!(store.list_users().unwrap(), vec![r.clone()]);
        assert!(store.delete_user(&r.root_pubkey_hex).unwrap());
        assert_eq!(store.get_user(&r.root_pubkey_hex).unwrap(), None);
        assert!(!store.delete_user(&r.root_pubkey_hex).unwrap());
    }

    #[test]
    fn missing_user_is_none_not_error_on_fresh_db() {
        let (_t, store) = s();
        assert_eq!(store.get_user("nope").unwrap(), None);
        assert_eq!(store.list_users().unwrap(), vec![]);
    }

    #[test]
    fn auth_session_roundtrip() {
        let (_t, store) = s();
        let sess = AuthSessionRecord {
            session_id: "s1".into(),
            client_id: "c1".into(),
            redirect_uri: "http://x".into(),
            code_challenge: "cc".into(),
            code_challenge_method: "S256".into(),
            resource: "https://mcp.example".into(),
            state: "st".into(),
            kind: AuthSessionKind::Pending,
            issued_at_ms: 1,
            expires_ms: 100,
        };
        store.put_auth_session(&sess).unwrap();
        assert_eq!(store.get_auth_session("s1").unwrap(), Some(sess));
    }

    #[test]
    fn refresh_tokens_revoke_for_sub_removes_only_matching() {
        let (_t, store) = s();
        let r1 = RefreshTokenRecord {
            token_hash_hex: "h1".into(),
            sub: "alice".into(),
            client_id: "c".into(),
            issued_at_ms: 1,
            expires_ms: 2,
            rotated_to_hash_hex: None,
        };
        let r2 = RefreshTokenRecord {
            token_hash_hex: "h2".into(),
            sub: "bob".into(),
            client_id: "c".into(),
            issued_at_ms: 1,
            expires_ms: 2,
            rotated_to_hash_hex: None,
        };
        store.put_refresh_token(&r1).unwrap();
        store.put_refresh_token(&r2).unwrap();
        let n = store.revoke_refresh_tokens_for_sub("alice").unwrap();
        assert_eq!(n, 1);
        assert!(store.get_refresh_token("h1").unwrap().is_none());
        assert!(store.get_refresh_token("h2").unwrap().is_some());
    }
}
