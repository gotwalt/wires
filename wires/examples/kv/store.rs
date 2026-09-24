//! The `kv` example's service: a key-value store held in the daemon's
//! memory, with one namespace per verified person, so each caller sees only
//! their own keys. A CLI wrapper couldn't do this cheaply: the state lives
//! across calls in one warm process, and the caller's identity arrives as a
//! type, not an environment variable to parse.
//!
//! Its own file so the e2e tests (`wires/e2e/native.rs`) serve this very
//! `Kv`; `main.rs` is the daemon around it.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A verified person: their IdP's issuer and subject.
type Person = (String, String);

/// One person's keys and values.
type Keys = BTreeMap<String, Vec<u8>>;

/// The store: each person's own keys.
#[derive(Default)]
pub struct Kv {
    people: Mutex<HashMap<Person, Keys>>,
}

/// The largest value `set` keeps.
const MAX_VALUE: u64 = 1024 * 1024;

impl wires::Service for Kv {
    async fn call(&self, call: wires::Call, mut io: wires::CallIo) -> i32 {
        let person = call.principal();
        let person = (person.issuer.clone(), person.subject.clone());
        let args: Vec<&str> = call.args().iter().map(String::as_str).collect();
        match args.as_slice() {
            ["set", key] => {
                let mut value = Vec::new();
                let read = (&mut io.stdin)
                    .take(MAX_VALUE + 1)
                    .read_to_end(&mut value)
                    .await;
                if read.is_err() || value.len() as u64 > MAX_VALUE {
                    let _ = io
                        .stderr
                        .write_all(b"kv: value unreadable or over 1 MiB\n")
                        .await;
                    return 1;
                }
                let mut people = self.people.lock().expect("kv poisoned");
                people
                    .entry(person)
                    .or_default()
                    .insert(key.to_string(), value);
                0
            }
            ["get", key] => {
                let value = {
                    let people = self.people.lock().expect("kv poisoned");
                    people.get(&person).and_then(|keys| keys.get(*key)).cloned()
                };
                match value {
                    Some(value) => io.stdout.write_all(&value).await.map_or(1, |()| 0),
                    None => {
                        let _ = io.stderr.write_all(b"kv: no such key\n").await;
                        1
                    }
                }
            }
            ["keys"] => {
                let listing: String = {
                    let people = self.people.lock().expect("kv poisoned");
                    people
                        .get(&person)
                        .map(|keys| keys.keys().map(|k| format!("{k}\n")).collect())
                        .unwrap_or_default()
                };
                io.stdout
                    .write_all(listing.as_bytes())
                    .await
                    .map_or(1, |()| 0)
            }
            _ => {
                let _ = io
                    .stderr
                    .write_all(b"usage: kv set KEY (value on stdin) | get KEY | keys\n")
                    .await;
                2
            }
        }
    }
}
