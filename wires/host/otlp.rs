//! Optional OTLP/HTTP (JSON) export of the host's call log (card 26a).
//!
//! With `"audit": {"otlp": "https://collector.example:4318"}` in `host.json`
//! (plain `http://` only to a collector on this machine), every
//! entry the host appends to its [call log](crate::host::call_log) is also
//! POSTed to `<endpoint>/v1/logs` as an OTLP `LogRecord`, so an org with a
//! SIEM gets identity-stamped call records where its other logs live.
//!
//! Each record's **body** is the signed [`LogEntry`] itself, as JSON, so the
//! record stays verifiable in the SIEM by anyone holding the host's public
//! key. Its **attributes** make it queryable (each only when the record
//! carries it: a `finished` record has no caller or tool, and pairs with its
//! `started` by `wires.call.id`):
//!
//! | attribute | from |
//! |---|---|
//! | `wires.host.node` | the host's node id (also a resource attribute) |
//! | `wires.record.seq`, `wires.record.hash`, `wires.record.prev`, `wires.record.signature` | the log entry |
//! | `wires.record.kind` | `started` / `finished` / `denied` / `push` |
//! | `wires.call.id` | started, finished |
//! | `wires.caller.node` | started, denied (the iroh-authenticated key) |
//! | `wires.principal.email`, `wires.principal.iss`, `wires.principal.sub` | started, push (when verified) |
//! | `wires.role` | started, push |
//! | `wires.service` | started, denied (when named) |
//! | `wires.argv` (string array) | started |
//! | `wires.exit`, `wires.duration_ms`, `wires.stdout.digest`, `wires.stdout.bytes` | finished |
//! | `wires.denied.reason` | denied |
//! | `wires.push.to`, `wires.push.subject`, `wires.push.outcome` | push |
//!
//! **Never in the way of a call.** [`Exporter::export`] only `try_send`s onto
//! a bounded queue ([`OTLP_QUEUE`]); a full queue drops the entry with a
//! warning (the host's own log still has it). A worker drains the queue in
//! batches of up to [`OTLP_BATCH`] records per POST; a failed POST is logged
//! and not retried.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use library::{AuditRecord, LogEntry, NodeId, Principal};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use url::Url;

/// How many entries may wait for the exporter before new ones are dropped.
pub const OTLP_QUEUE: usize = 1024;

/// The most log records sent in one POST.
pub const OTLP_BATCH: usize = 64;

/// The OTLP/HTTP logs path appended to the configured endpoint.
const LOGS_PATH: &str = "v1/logs";

/// The instrumentation scope every record is filed under.
const SCOPE: &str = "wires.call_log";

/// The OTLP logs URL for a configured collector `endpoint`: `https`, or
/// plain `http` only to a loopback host (`localhost`, `127.0.0.0/8`, `::1`):
/// the records carry callers' identities and arguments, so they don't cross
/// a network in the clear. `/v1/logs` is appended unless the path already
/// ends with it.
pub fn logs_url(endpoint: &str) -> Result<Url> {
    let mut url = Url::parse(endpoint).with_context(|| format!("{endpoint:?} is not a URL"))?;
    match url.scheme() {
        "https" => {}
        "http" if crate::net::is_loopback(&url) => {}
        "http" => bail!(
            "{endpoint:?}: plain http:// is allowed only to a collector on this machine \
             (localhost, 127.0.0.1, [::1]); use https://"
        ),
        _ => bail!("{endpoint:?}: an OTLP/HTTP endpoint is https:// (or http:// to localhost)"),
    }
    if !url.path().trim_end_matches('/').ends_with(LOGS_PATH) {
        let path = format!("{}/{LOGS_PATH}", url.path().trim_end_matches('/'));
        url.set_path(&path);
    }
    Ok(url)
}

/// The sending side of the exporter: cheap to hold, never blocks.
#[derive(Clone, Debug)]
pub struct Exporter {
    /// The bounded queue to the worker.
    tx: mpsc::Sender<LogEntry>,
    /// Entries dropped because the queue was full or closed.
    dropped: Arc<AtomicU64>,
}

impl Exporter {
    /// An exporter and the receiver its worker ([`run`]) drains.
    pub fn channel(cap: usize) -> (Self, mpsc::Receiver<LogEntry>) {
        let (tx, rx) = mpsc::channel(cap);
        (
            Self {
                tx,
                dropped: Arc::default(),
            },
            rx,
        )
    }

    /// An exporter to `endpoint` (a collector base URL), with its worker
    /// spawned on the current runtime.
    pub fn spawn(endpoint: &str) -> Result<(Self, JoinHandle<()>)> {
        let url = logs_url(endpoint)?;
        let http = crate::caller::jwks::http_client()?;
        let (exporter, rx) = Self::channel(OTLP_QUEUE);
        tracing::info!(%url, "exporting the call log over OTLP/HTTP");
        Ok((exporter, tokio::spawn(run(rx, url, http))))
    }

    /// Queue `entry` for export without waiting; drop it (with a warning)
    /// when the queue is full or the worker is gone.
    pub fn export(&self, entry: LogEntry) {
        if let Err(e) = self.tx.try_send(entry) {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            let why = match e {
                mpsc::error::TrySendError::Full(_) => "queue full",
                mpsc::error::TrySendError::Closed(_) => "exporter stopped",
            };
            tracing::warn!(dropped = n, "OTLP export dropped a call record ({why})");
        }
    }

    /// How many entries have been dropped so far (the warning logs it too).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// The exporter's worker: POST queued entries to `url` in batches until the
/// queue closes. Failures are logged, never retried.
pub async fn run(mut rx: mpsc::Receiver<LogEntry>, url: Url, http: reqwest::Client) {
    let mut batch = Vec::with_capacity(OTLP_BATCH);
    while rx.recv_many(&mut batch, OTLP_BATCH).await > 0 {
        let body = request(&batch);
        match http.post(url.clone()).json(&body).send().await {
            Ok(r) if r.status().is_success() => {
                tracing::debug!(records = batch.len(), "OTLP export sent");
            }
            Ok(r) => tracing::warn!(
                status = %r.status(),
                records = batch.len(),
                "OTLP collector refused call records"
            ),
            Err(e) => tracing::warn!(records = batch.len(), "OTLP export failed: {e}"),
        }
        batch.clear();
    }
}

/// An OTLP `ExportLogsServiceRequest` (JSON encoding) for `entries`, grouped
/// under one resource per host.
pub fn request(entries: &[LogEntry]) -> Value {
    let mut hosts: Vec<NodeId> = entries.iter().map(|e| e.host).collect();
    hosts.sort();
    hosts.dedup();
    let resource_logs: Vec<Value> = hosts
        .into_iter()
        .map(|host| {
            let records: Vec<Value> = entries
                .iter()
                .filter(|e| e.host == host)
                .map(log_record)
                .collect();
            json!({
                "resource": { "attributes": [
                    kv("service.name", string("wires-host")),
                    kv("wires.host.node", string(host.hex())),
                ]},
                "scopeLogs": [{
                    "scope": { "name": SCOPE, "version": env!("CARGO_PKG_VERSION") },
                    "logRecords": records,
                }],
            })
        })
        .collect();
    json!({ "resourceLogs": resource_logs })
}

/// One entry as an OTLP `LogRecord`. See the module docs for the attributes.
pub fn log_record(entry: &LogEntry) -> Value {
    let mut attrs = vec![
        kv("wires.host.node", string(entry.host.hex())),
        kv("wires.record.seq", int(entry.seq.0 as i64)),
        kv("wires.record.prev", string(entry.prev.hex())),
        kv("wires.record.signature", string(entry.sig.hex())),
    ];
    if let Ok(hash) = entry.hash() {
        attrs.push(kv("wires.record.hash", string(hash.hex())));
    }
    let (kind, summary, warn) = match &entry.record {
        AuditRecord::Started {
            call,
            caller,
            principal,
            service,
            argv,
            role,
            ..
        } => {
            attrs.push(kv("wires.call.id", string(call.hex())));
            attrs.push(kv("wires.caller.node", string(caller.hex())));
            principal_attrs(&mut attrs, principal.as_ref());
            attrs.push(kv("wires.role", string(role.as_str())));
            attrs.push(kv("wires.service", string(service.as_str())));
            let args: Vec<Value> = argv.as_slice().iter().map(string).collect();
            attrs.push(kv(
                "wires.argv",
                json!({ "arrayValue": { "values": args } }),
            ));
            ("started", format!("call started: {service}"), false)
        }
        AuditRecord::Finished {
            call,
            exit,
            duration_ms,
            stdout_bytes,
            stdout_digest,
            ..
        } => {
            attrs.push(kv("wires.call.id", string(call.hex())));
            attrs.push(kv("wires.exit", int(i64::from(*exit))));
            attrs.push(kv("wires.duration_ms", int(*duration_ms as i64)));
            attrs.push(kv("wires.stdout.digest", string(stdout_digest.hex())));
            attrs.push(kv("wires.stdout.bytes", int(*stdout_bytes as i64)));
            (
                "finished",
                format!("call finished: exit {exit}"),
                *exit != 0,
            )
        }
        AuditRecord::Denied {
            caller,
            service,
            reason,
            ..
        } => {
            attrs.push(kv("wires.caller.node", string(caller.hex())));
            if let Some(service) = service {
                attrs.push(kv("wires.service", string(service.as_str())));
            }
            attrs.push(kv("wires.denied.reason", string(reason)));
            ("denied", format!("call denied: {reason}"), true)
        }
        AuditRecord::Push {
            to,
            principal,
            role,
            subject,
            outcome,
            ..
        } => {
            attrs.push(kv("wires.push.to", string(to.hex())));
            principal_attrs(&mut attrs, principal.as_ref());
            if let Some(role) = role {
                attrs.push(kv("wires.role", string(role)));
            }
            attrs.push(kv("wires.push.subject", string(subject.as_str())));
            attrs.push(kv("wires.push.outcome", string(outcome.as_str())));
            let warn = matches!(outcome, library::PushOutcome::Denied);
            ("push", format!("push {}", outcome.as_str()), warn)
        }
    };
    attrs.insert(0, kv("wires.record.kind", string(kind)));
    let nanos = (entry.at_ms.max(0) as u64)
        .saturating_mul(1_000_000)
        .to_string();
    let (severity, severity_text) = if warn { (13, "WARN") } else { (9, "INFO") };
    let body = serde_json::to_string(entry).unwrap_or(summary);
    json!({
        "timeUnixNano": nanos,
        "observedTimeUnixNano": nanos,
        "severityNumber": severity,
        "severityText": severity_text,
        "body": string(body),
        "attributes": attrs,
    })
}

/// `wires.principal.*` for a verified identity, when there is one.
fn principal_attrs(attrs: &mut Vec<Value>, principal: Option<&Principal>) {
    if let Some(p) = principal {
        if let Some(email) = &p.email {
            attrs.push(kv("wires.principal.email", string(email)));
        }
        attrs.push(kv("wires.principal.iss", string(&p.issuer)));
        attrs.push(kv("wires.principal.sub", string(&p.subject)));
    }
}

/// An OTLP `KeyValue`.
fn kv(key: &str, value: Value) -> Value {
    json!({ "key": key, "value": value })
}

/// An OTLP string `AnyValue`.
fn string(s: impl AsRef<str>) -> Value {
    json!({ "stringValue": s.as_ref() })
}

/// An OTLP int `AnyValue` (int64 is a JSON string in OTLP/JSON).
fn int(n: i64) -> Value {
    json!({ "intValue": n.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::login::{read_request, write_response};
    use library::{Argv, CallId, NodeIdentity, OutputHasher, ServiceName};
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn host() -> NodeIdentity {
        NodeIdentity::from_seed([11u8; 32])
    }

    fn caller() -> NodeId {
        NodeIdentity::from_seed([12u8; 32]).node_id()
    }

    fn call() -> CallId {
        CallId::from_hex("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn started() -> AuditRecord {
        AuditRecord::Started {
            call: call(),
            caller: caller(),
            principal: Some(Principal {
                issuer: "https://idp.example".into(),
                subject: "sub-1".into(),
                email: Some("alice@example.com".into()),
                org: None,
                groups: vec![],
                not_after: 0,
                claims: Default::default(),
            }),
            service: ServiceName::new("db_query").unwrap(),
            argv: Argv::new(vec!["select 1".into(), "-n".into()]).unwrap(),
            state_version: library::StateVersion(1),
            role: library::RoleName::new("analyst").unwrap(),
            at_ms: 5,
        }
    }

    fn finished() -> AuditRecord {
        let mut out = OutputHasher::new();
        out.update(b"1\n");
        AuditRecord::Finished {
            call: call(),
            exit: 0,
            duration_ms: 41,
            stdout_bytes: 2,
            stderr_bytes: 0,
            stdout_digest: out.finish(),
            stdin_bytes: 0,
            stdin_digest: OutputHasher::new().finish(),
            stdin_head: None,
        }
    }

    fn entries() -> Vec<LogEntry> {
        let h = host();
        let a = LogEntry::next(&h, None, 1_700_000_000_000, started()).unwrap();
        let b =
            LogEntry::next(&h, Some(a.point().unwrap()), 1_700_000_000_041, finished()).unwrap();
        vec![a, b]
    }

    /// `key → value` for a log record's attributes, values as their JSON.
    fn attributes(record: &Value) -> BTreeMap<String, Value> {
        record["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|kv| (kv["key"].as_str().unwrap().to_string(), kv["value"].clone()))
            .collect()
    }

    #[test]
    fn logs_url_appends_the_logs_path_once() {
        let u = |s| logs_url(s).unwrap().to_string();
        assert_eq!(u("http://127.0.0.1:4318"), "http://127.0.0.1:4318/v1/logs");
        assert_eq!(u("http://localhost:4318/"), "http://localhost:4318/v1/logs");
        assert_eq!(u("http://[::1]:4318"), "http://[::1]:4318/v1/logs");
        assert_eq!(
            u("https://c.example/otel/v1/logs"),
            "https://c.example/otel/v1/logs"
        );
        assert_eq!(
            u("https://c.example/otel"),
            "https://c.example/otel/v1/logs"
        );
        assert!(logs_url("collector:4318/x").is_err());
        assert!(logs_url("not a url").is_err());
    }

    /// Card 28 §10: records don't cross a network in the clear.
    #[test]
    fn plain_http_is_only_for_a_loopback_collector() {
        for bad in [
            "http://collector:4318",
            "http://10.0.0.5:4318",
            "http://[2001:db8::1]:4318",
            "http://localhost.evil.example:4318",
        ] {
            let e = format!("{:#}", logs_url(bad).unwrap_err());
            assert!(e.contains("https://"), "{bad}: {e}");
        }
        assert!(logs_url("https://collector:4318").is_ok());
        assert!(logs_url("ftp://localhost").is_err());
    }

    /// Known answer: a `started` and its `finished`, attribute by attribute.
    #[test]
    fn records_carry_the_listed_attributes() {
        let es = entries();
        let a = attributes(&log_record(&es[0]));
        let s = |k: &str| a[k]["stringValue"].as_str().unwrap().to_string();
        assert_eq!(s("wires.record.kind"), "started");
        assert_eq!(s("wires.caller.node"), caller().hex());
        assert_eq!(s("wires.principal.email"), "alice@example.com");
        assert_eq!(s("wires.principal.iss"), "https://idp.example");
        assert_eq!(s("wires.principal.sub"), "sub-1");
        assert_eq!(s("wires.role"), "analyst");
        assert_eq!(s("wires.service"), "db_query");
        assert_eq!(
            a["wires.argv"],
            json!({"arrayValue": {"values": [
                {"stringValue": "select 1"}, {"stringValue": "-n"}
            ]}})
        );
        assert_eq!(s("wires.host.node"), host().node_id().hex());
        assert_eq!(a["wires.record.seq"], json!({"intValue": "0"}));
        assert_eq!(s("wires.record.hash"), es[0].hash().unwrap().hex());
        assert_eq!(s("wires.record.signature"), es[0].sig.hex());
        assert_eq!(s("wires.call.id"), call().hex());

        let record = log_record(&es[1]);
        let b = attributes(&record);
        assert_eq!(b["wires.record.kind"]["stringValue"], "finished");
        assert_eq!(b["wires.exit"], json!({"intValue": "0"}));
        assert_eq!(b["wires.duration_ms"], json!({"intValue": "41"}));
        let mut out = OutputHasher::new();
        out.update(b"1\n");
        assert_eq!(b["wires.stdout.digest"]["stringValue"], out.finish().hex());
        assert_eq!(b["wires.record.seq"], json!({"intValue": "1"}));
        assert_eq!(record["timeUnixNano"], "1700000000041000000");
        assert_eq!(record["severityText"], "INFO");
        // The body is the signed entry: verifiable wherever it lands.
        let body: LogEntry =
            serde_json::from_str(record["body"]["stringValue"].as_str().unwrap()).unwrap();
        assert_eq!(body, es[1]);
        body.verify().unwrap();
    }

    #[test]
    fn a_denial_is_a_warning_with_its_reason() {
        let e = LogEntry::next(
            &host(),
            None,
            1,
            AuditRecord::Denied {
                caller: caller(),
                principal: None,
                service: Some(ServiceName::new("db_query").unwrap()),
                reason: "no role allows db_query".into(),
                at_ms: 1,
            },
        )
        .unwrap();
        let r = log_record(&e);
        assert_eq!(r["severityText"], "WARN");
        let a = attributes(&r);
        assert_eq!(
            a["wires.denied.reason"]["stringValue"],
            "no role allows db_query"
        );
        assert_eq!(a["wires.service"]["stringValue"], "db_query");
        assert!(!a.contains_key("wires.principal.email"));
    }

    /// The exporter never blocks: past its queue, entries are dropped and
    /// counted.
    #[test]
    fn a_full_queue_drops_and_counts() {
        let (x, _rx) = Exporter::channel(1);
        let es = entries();
        x.export(es[0].clone());
        x.export(es[1].clone());
        assert_eq!(x.dropped(), 1);
        drop(_rx);
        x.export(es[0].clone());
        assert_eq!(x.dropped(), 2);
    }

    /// A mock OTLP/HTTP collector receives each entry, in order, at
    /// `/v1/logs`, with the attributes the card lists.
    #[tokio::test]
    async fn entries_arrive_at_a_mock_collector() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (got_tx, mut got) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let req = read_request(&mut stream).await.unwrap();
                write_response(&mut stream, 200, "application/json", &[], b"{}")
                    .await
                    .unwrap();
                let _ = got_tx.send(req);
            }
        });
        let (x, worker) = Exporter::spawn(&format!("http://{addr}")).unwrap();
        for e in entries() {
            x.export(e);
        }
        let mut records = Vec::new();
        while records.len() < 2 {
            let req = tokio::time::timeout(Duration::from_secs(10), got.recv())
                .await
                .expect("the collector heard nothing")
                .unwrap();
            assert_eq!(req.method, "POST");
            assert_eq!(req.target, "/v1/logs");
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let rl = &body["resourceLogs"][0];
            assert_eq!(
                attributes(&rl["resource"])["wires.host.node"]["stringValue"],
                host().node_id().hex()
            );
            records.extend(
                rl["scopeLogs"][0]["logRecords"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .cloned(),
            );
        }
        let seqs: Vec<Value> = records
            .iter()
            .map(|r| attributes(r)["wires.record.seq"].clone())
            .collect();
        assert_eq!(seqs, [json!({"intValue": "0"}), json!({"intValue": "1"})]);
        assert_eq!(
            attributes(&records[0])["wires.principal.email"]["stringValue"],
            "alice@example.com"
        );
        assert_eq!(x.dropped(), 0);
        drop(x);
        worker.await.unwrap();
        server.abort();
    }

    /// A collector that is down costs a warning, not a stuck worker.
    #[tokio::test]
    async fn an_unreachable_collector_does_not_stop_the_worker() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (x, worker) = Exporter::spawn(&format!("http://{addr}")).unwrap();
        for e in entries() {
            x.export(e);
        }
        drop(x);
        tokio::time::timeout(Duration::from_secs(30), worker)
            .await
            .expect("the worker finished")
            .unwrap();
    }

    proptest! {
        /// Every entry becomes exactly one log record, under its host's
        /// resource, whatever the mix of hosts.
        #[test]
        fn one_record_per_entry(hosts in proptest::collection::vec(0u8..3, 0..12)) {
            let mut tips = [None; 3];
            let entries: Vec<LogEntry> = hosts
                .iter()
                .map(|h| {
                    let id = NodeIdentity::from_seed([*h + 20; 32]);
                    let e = LogEntry::next(&id, tips[*h as usize], 1, finished()).unwrap();
                    tips[*h as usize] = Some(e.point().unwrap());
                    e
                })
                .collect();
            let req = request(&entries);
            let resources = req["resourceLogs"].as_array().unwrap();
            let mut distinct = hosts.clone();
            distinct.sort();
            distinct.dedup();
            prop_assert_eq!(resources.len(), distinct.len());
            let total: usize = resources
                .iter()
                .map(|r| r["scopeLogs"][0]["logRecords"].as_array().unwrap().len())
                .sum();
            prop_assert_eq!(total, entries.len());
            for r in resources {
                let host = attributes(&r["resource"])["wires.host.node"]["stringValue"].clone();
                for rec in r["scopeLogs"][0]["logRecords"].as_array().unwrap() {
                    prop_assert_eq!(&attributes(rec)["wires.host.node"]["stringValue"], &host);
                }
            }
        }
    }
}
