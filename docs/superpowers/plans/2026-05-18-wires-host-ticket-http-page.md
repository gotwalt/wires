# Host-Ticket HTTP Page — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an always-on, LAN-bound HTTP server to `wires-host` that serves the live `HostTicket` as a QR-first web page (`GET /`) plus two raw companion routes (`GET /ticket.txt`, `GET /ticket.svg`). The page is mobile-first, self-contained (inline CSS+JS, no external assets), and exposes a copy-to-clipboard button plus a collapsible base64 view.

**Architecture:** A new module `wires-host::ticket_http` builds an `axum::Router` with three routes; each handler holds an `Arc<AppState>` containing the live `iroh::Endpoint` and the configured hint TTL, and rebuilds the ticket on every request. Lifecycle is managed via a shared `tokio_util::sync::CancellationToken` fired by a `tokio::signal::ctrl_c()` task that this plan adds. A small `HostTicket::render_qr_svg` helper lands in `wires-net::ticket` so the SVG renderer lives next to the existing `render_qr_ansi`.

**Tech Stack:** Rust edition 2024 / stable 1.95, iroh 0.98, snafu, serde+serde_json, `qrcode = "0.14"` (already in `wires-net`), `axum = "0.8"` (new on `wires-host`), `tokio_util = "0.7"` (new on `wires-host`, `sync` feature only), `reqwest = "0.12"` (dev-dep on `wires-host`).

**Spec:** `docs/superpowers/specs/2026-05-18-wires-host-ticket-http-page-design.md`

---

## File Map

| File | Action | Owner task |
|---|---|---|
| `crates/wires-net/src/ticket.rs` | Modify: add `HostTicket::render_qr_svg` + test | Task 1 |
| `crates/wires-host/Cargo.toml` | Modify: add `axum`, `tokio-util`; dev-dep `reqwest` | Task 2 |
| `crates/wires-host/src/error.rs` | Modify: add `HttpBind`, `HttpServe`, `QrSvg` variants | Task 3 |
| `crates/wires-host/src/lib.rs` | Modify: `pub mod ticket_http;` | Task 4 |
| `crates/wires-host/src/ticket_http.rs` | Create: `spawn` + `/ticket.txt` route | Task 4 |
| `crates/wires-host/tests/ticket_http.rs` | Create: integration test (all three routes) | Tasks 4–6 |
| `crates/wires-host/src/ticket_http.rs` | Modify: add `/ticket.svg` route | Task 5 |
| `crates/wires-host/src/ticket_http.rs` | Modify: add `/` (HTML page) route | Task 6 |
| `crates/wires-host/src/main.rs` | Modify: CLI flags, CancellationToken, spawn HTTP task | Task 7 |

No file is touched outside the `wires-net::ticket` SVG helper and the `wires-host` crate.

---

## Phase A — Helper in `wires-net`

### Task 1: Add `HostTicket::render_qr_svg` to wires-net

**Files:**
- Modify: `crates/wires-net/src/ticket.rs`

- [ ] **Step 1: Add the failing test**

Append this test inside the existing `#[cfg(test)] mod tests` block at the bottom of `crates/wires-net/src/ticket.rs`, alongside `render_qr_ansi_produces_block_art`:

```rust
#[test]
fn render_qr_svg_produces_svg() {
    let t = sample();
    let s = t.render_qr_svg().unwrap();
    assert!(!s.is_empty(), "rendered SVG must be non-empty");
    assert!(
        s.starts_with("<?xml") || s.starts_with("<svg"),
        "expected SVG to start with <?xml or <svg, got {:?}",
        &s[..s.len().min(40)]
    );
    assert!(
        s.contains("<rect") || s.contains("<path"),
        "SVG should contain at least one <rect> or <path>"
    );
    // Sanity-check that the dark/light colors land in the output so the
    // wires-host module's post-processing has something to str::replace on.
    assert!(s.contains("#1c1c1c"), "expected dark color to appear");
    assert!(s.contains("#ffffff"), "expected light color to appear");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-net --lib render_qr_svg_produces_svg`
Expected: FAIL with "no method named `render_qr_svg` found".

- [ ] **Step 3: Implement `render_qr_svg`**

In `crates/wires-net/src/ticket.rs`, add this method on `impl HostTicket`, immediately after `render_qr_ansi` (which ends at line 154):

```rust
    /// Render the encoded ticket as a standalone SVG QR. Dark modules are
    /// `#1c1c1c`; light modules are `#ffffff`. Callers that inline this SVG
    /// into HTML and want it to follow the page's text color should
    /// post-process: `str::replace("#1c1c1c", "currentColor")` and
    /// `str::replace("#ffffff", "transparent")`.
    pub fn render_qr_svg(&self) -> Result<String> {
        let payload = self.encode()?;
        let code = qrcode::QrCode::new(payload.as_bytes()).context(TicketQrRenderSnafu)?;
        let svg = code
            .render::<qrcode::render::svg::Color>()
            .quiet_zone(true)
            .dark_color(qrcode::render::svg::Color("#1c1c1c"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build();
        Ok(svg)
    }
```

The `qrcode` crate's `render::svg::Color` is a tuple struct wrapping `&'static str`; passing a string literal works directly. No new error variant — `TicketQrRender` already exists.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p wires-net --lib render_qr_svg_produces_svg`
Expected: PASS (1 passed; 0 failed).

- [ ] **Step 5: Run the surrounding ticket tests to make sure nothing broke**

Run: `cargo test -p wires-net --lib ticket::`
Expected: All ticket tests pass (10 passed).

- [ ] **Step 6: Commit**

```bash
git add crates/wires-net/src/ticket.rs
git commit -m "wires-net: HostTicket::render_qr_svg"
```

---

## Phase B — `wires-host` deps and errors

### Task 2: Add HTTP dependencies to wires-host

**Files:**
- Modify: `crates/wires-host/Cargo.toml`

- [ ] **Step 1: Add axum and tokio-util under `[dependencies]`**

Open `crates/wires-host/Cargo.toml`. In the `[dependencies]` block, add the following lines (place them alphabetically, after `clap` and before `humantime`):

```toml
axum       = { version = "0.8", default-features = false, features = ["http1", "tokio"] }
tokio-util = { version = "0.7", default-features = false, features = ["rt"] }
```

axum 0.8 needs `tokio` for `axum::serve` and `http1` for HTTP/1.1 wire support; the `Router::new()` / `get()` builders themselves don't need extra features. `tokio-util`'s `rt` feature brings in `CancellationToken`. If `CancellationToken` is missing from the resulting feature set, fall back to `features = ["rt", "sync"]`.

- [ ] **Step 2: Add reqwest under `[dev-dependencies]`**

In the `[dev-dependencies]` block of `crates/wires-host/Cargo.toml`, add:

```toml
reqwest   = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

No `blocking` feature — the integration test runs inside a `#[tokio::test]` and uses the async client.

- [ ] **Step 3: Verify the workspace still builds**

Run: `cargo build -p wires-host`
Expected: builds clean (some "unused dependency" warnings from axum/tokio-util are OK at this stage — Tasks 4–7 consume them).

- [ ] **Step 4: Commit**

```bash
git add crates/wires-host/Cargo.toml Cargo.lock
git commit -m "wires-host: add axum + tokio-util deps, reqwest dev-dep"
```

---

### Task 3: Add new `HostError` variants

**Files:**
- Modify: `crates/wires-host/src/error.rs`

- [ ] **Step 1: Add the three new variants**

Open `crates/wires-host/src/error.rs`. After the existing `Io` variant (line 89) and before the closing `}` of the `HostError` enum, insert:

```rust
    #[snafu(display("Failed to bind ticket-http listener on {bind}: {source}, at {location}"))]
    HttpBind {
        bind: std::net::SocketAddr,
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("ticket-http server failed: {source}, at {location}"))]
    HttpServe {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to render host-ticket SVG: {source}, at {location}"))]
    QrSvg {
        #[snafu(source)]
        source: wires_net::NetError,
        #[snafu(implicit)]
        location: Location,
    },
```

These follow the existing snafu shape in this file: every variant has `#[snafu(implicit)] location: Location`, no `message:` field, and the display string ends with `, at {location}`.

- [ ] **Step 2: Verify the crate compiles**

Run: `cargo build -p wires-host`
Expected: builds clean. (The variants are pub(crate) and currently unused; warnings are fine.)

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/src/error.rs
git commit -m "wires-host: HostError variants for HTTP bind/serve and QR SVG"
```

---

## Phase C — The HTTP module

This phase builds the module in three slices: skeleton + `/ticket.txt`, then `/ticket.svg`, then `/`. Each slice TDD'd through one growing integration test.

### Task 4: Skeleton + `/ticket.txt` route

**Files:**
- Modify: `crates/wires-host/src/lib.rs`
- Create: `crates/wires-host/src/ticket_http.rs`
- Create: `crates/wires-host/tests/ticket_http.rs`

- [ ] **Step 1: Add the module declaration**

Open `crates/wires-host/src/lib.rs`. Add the following line alongside the other `pub mod` declarations (alphabetical order, so somewhere near `pub mod tenant_registry;`):

```rust
pub mod ticket_http;
```

- [ ] **Step 2: Write the failing integration test (single big test, expands across Tasks 4–6)**

Create `crates/wires-host/tests/ticket_http.rs` with this content. This is the **complete** test file; Tasks 5 and 6 will add `assert` blocks inside the same test function (they will not add additional test functions).

```rust
//! Integration test for the wires-host ticket HTTP server.
//!
//! Spins up a single iroh endpoint and a `ticket_http::spawn` server on
//! 127.0.0.1:0, then GETs each route once. One iroh warm-up amortized
//! across all three assertions keeps the test runnable in CI cold-starts.

use std::time::Duration;

use iroh::SecretKey;
use tokio_util::sync::CancellationToken;
use wires_host::ticket_http;
use wires_net::HostTicket;

#[tokio::test]
async fn ticket_http_serves_all_three_routes() {
    let _ = tracing_subscriber::fmt::try_init();

    // Bring up an iroh endpoint. bind_lan pays the 5-30s cold-start cost
    // documented in the project CLAUDE.md. Matches the pattern in
    // wires-net/src/ticket.rs::from_endpoint_roundtrips_endpoint_id.
    let endpoint = wires_net::bind_lan(SecretKey::generate(), vec![])
        .await
        .expect("bind_lan failed");
    let endpoint_id_hex = hex::encode(endpoint.id().as_bytes());

    let shutdown = CancellationToken::new();
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound, handle) =
        ticket_http::spawn(endpoint.clone(), bind, Duration::from_secs(60), shutdown.clone())
            .await
            .expect("ticket_http::spawn failed");

    let client = reqwest::Client::new();

    // /ticket.txt — body decodes back to a HostTicket and the endpoint_id matches.
    let resp = client
        .get(format!("http://{bound}/ticket.txt"))
        .send()
        .await
        .expect("GET /ticket.txt failed");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("")
            .starts_with("text/plain"),
        "expected text/plain content-type"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap_or("")),
        Some("no-store"),
    );
    let body = resp.text().await.expect("body");
    let ticket = HostTicket::decode(body.trim()).expect("decode HostTicket");
    assert_eq!(ticket.endpoint_id, endpoint_id_hex);

    // Tasks 5 and 6 extend this test in place below.

    shutdown.cancel();
    handle.await.expect("HTTP task panicked").expect("HTTP task returned error");
}
```

- [ ] **Step 3: Run the test to verify it fails (compile error — no `ticket_http` module yet)**

Run: `cargo test -p wires-host --test ticket_http`
Expected: FAIL with "unresolved import `wires_host::ticket_http`" or similar.

- [ ] **Step 4: Create the `ticket_http` module**

Create `crates/wires-host/src/ticket_http.rs` with this content:

```rust
//! Always-on LAN HTTP server that exposes the host's `HostTicket` as a
//! QR-first web page plus two raw routes. Bound to `--http-bind` (default
//! `0.0.0.0:8089`); lives as long as the host process.
//!
//! See `docs/superpowers/specs/2026-05-18-wires-host-ticket-http-page-design.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use snafu::ResultExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wires_net::HostTicket;

use crate::error::{HostError, HttpBindSnafu, HttpServeSnafu, QrSvgSnafu, Result};

struct AppState {
    endpoint: iroh::Endpoint,
    hint_ttl: Duration,
}

/// Bind a TCP listener, spawn the axum server, and return both the bound
/// address (resolved from the listener — important when `bind` uses port 0)
/// and the JoinHandle for the server task.
///
/// The server runs until `shutdown` is cancelled. Graceful shutdown drains
/// in-flight requests.
pub async fn spawn(
    endpoint: iroh::Endpoint,
    bind: SocketAddr,
    hint_ttl: Duration,
    shutdown: CancellationToken,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(bind).await.context(HttpBindSnafu { bind })?;
    let bound = listener.local_addr().context(HttpBindSnafu { bind })?;
    let state = Arc::new(AppState { endpoint, hint_ttl });
    let router = build_router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await
            .context(HttpServeSnafu)?;
        Ok(())
    });
    Ok((bound, handle))
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ticket.txt", get(serve_txt))
        .with_state(state)
}

/// Build the current ticket from the live endpoint. Re-derived per request.
fn current_ticket(state: &AppState) -> Result<HostTicket> {
    HostTicket::from_endpoint(&state.endpoint, state.hint_ttl).context(QrSvgSnafu)
}

async fn serve_txt(State(state): State<Arc<AppState>>) -> Result<Response> {
    let ticket = current_ticket(&state)?;
    let body = ticket.encode().context(QrSvgSnafu)?;
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

impl IntoResponse for HostError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self, "ticket-http handler failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error rendering host ticket",
        )
            .into_response()
    }
}
```

A note on `QrSvgSnafu`: the spec named that variant for SVG-rendering errors, but it carries `wires_net::NetError` as its source, and `HostTicket::from_endpoint` and `HostTicket::encode` both return `wires_net::Result`. Reusing one snafu for any wires-net-side ticket failure inside the handlers keeps the handler code uniform; the variant name is a slight stretch for the `encode` path but it correctly identifies the layer and the failure is theoretical anyway. Acceptable.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p wires-host --test ticket_http`
Expected: PASS (1 passed). The iroh cold-start may take 5–30s on first run; CLAUDE.md documents this.

- [ ] **Step 6: Run a wider test sweep to confirm nothing else broke**

Run: `cargo test -p wires-host`
Expected: all wires-host tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-host/src/lib.rs crates/wires-host/src/ticket_http.rs crates/wires-host/tests/ticket_http.rs
git commit -m "wires-host: ticket_http module skeleton + /ticket.txt route"
```

---

### Task 5: Add `/ticket.svg` route

**Files:**
- Modify: `crates/wires-host/src/ticket_http.rs`
- Modify: `crates/wires-host/tests/ticket_http.rs`

- [ ] **Step 1: Extend the integration test with `/ticket.svg` assertions**

Open `crates/wires-host/tests/ticket_http.rs`. Find the comment `// Tasks 5 and 6 extend this test in place below.` and replace **just that comment line** with:

```rust
    // /ticket.svg — SVG content with the right content-type and no-store cache header.
    let resp = client
        .get(format!("http://{bound}/ticket.svg"))
        .send()
        .await
        .expect("GET /ticket.svg failed");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("")
            .starts_with("image/svg+xml"),
        "expected image/svg+xml content-type"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap_or("")),
        Some("no-store"),
    );
    let body = resp.text().await.expect("body");
    assert!(
        body.starts_with("<?xml") || body.starts_with("<svg"),
        "expected SVG header, got {:?}",
        &body[..body.len().min(40)]
    );
    assert!(body.contains("<rect") || body.contains("<path"));

    // Task 6 extends this test in place below.
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-host --test ticket_http`
Expected: FAIL with `assertion failed: assert_eq!(resp.status(), 200)` and a 404 (axum returns 404 for an unregistered route).

- [ ] **Step 3: Implement the route**

In `crates/wires-host/src/ticket_http.rs`, add the handler after `serve_txt`:

```rust
async fn serve_svg(State(state): State<Arc<AppState>>) -> Result<Response> {
    let ticket = current_ticket(&state)?;
    let svg = ticket.render_qr_svg().context(QrSvgSnafu)?;
    let mut resp = svg.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}
```

And register it in `build_router`:

```rust
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ticket.txt", get(serve_txt))
        .route("/ticket.svg", get(serve_svg))
        .with_state(state)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p wires-host --test ticket_http`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/src/ticket_http.rs crates/wires-host/tests/ticket_http.rs
git commit -m "wires-host: /ticket.svg route"
```

---

### Task 6: Add `/` (HTML page) route

**Files:**
- Modify: `crates/wires-host/src/ticket_http.rs`
- Modify: `crates/wires-host/tests/ticket_http.rs`

- [ ] **Step 1: Extend the integration test with `/` assertions**

Open `crates/wires-host/tests/ticket_http.rs`. Replace **just the line** `    // Task 6 extends this test in place below.` with:

```rust
    // / — full HTML page. Asserts on structural markers, since the exact
    // base64 differs from request to request (issued_at advances).
    let resp = client
        .get(format!("http://{bound}/"))
        .send()
        .await
        .expect("GET / failed");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("")
            .starts_with("text/html"),
        "expected text/html content-type"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap_or("")),
        Some("no-store"),
    );
    let html = resp.text().await.expect("body");
    assert!(html.contains("<!doctype html>"), "missing doctype");
    assert!(html.contains("Scan with"), "missing caption");
    assert!(html.contains("Copy ticket"), "missing copy button label");
    assert!(html.contains("Show ticket text"), "missing ticket-text disclosure");
    assert!(html.contains("Host details"), "missing host-details disclosure");
    assert!(html.contains("<svg"), "missing inline QR svg");
    // Endpoint id (the half that doesn't change per-request) should appear.
    assert!(html.contains(&endpoint_id_hex), "endpoint id not rendered");
    // The dark-mode post-processing should have removed the raw color literals.
    assert!(!html.contains("#1c1c1c"), "dark-color literal leaked into HTML");
    assert!(!html.contains("#ffffff"), "light-color literal leaked into HTML");
    assert!(html.contains("currentColor"), "missing currentColor substitution");
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-host --test ticket_http`
Expected: FAIL with `assert_eq!(resp.status(), 200)` (route unregistered → 404).

- [ ] **Step 3: Add the HTML template**

In `crates/wires-host/src/ticket_http.rs`, near the top of the file (after the imports, before the `AppState` struct), add the template as a single const:

```rust
const HTML_TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wires host</title>
<style>
:root {
    --bg: #fafafa;
    --fg: #1c1c1c;
    --muted: #666;
    --accent: #3b6ea8;
    --accent-fg: #ffffff;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg: #0e0e10;
        --fg: #eaeaea;
        --muted: #999;
    }
}
* { box-sizing: border-box; }
html, body {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
body {
    padding: 24px;
    max-width: 480px;
    margin: 0 auto;
}
header {
    color: var(--muted);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 24px;
}
.qr-wrap {
    display: flex;
    justify-content: center;
    margin: 0 0 16px 0;
}
.qr-wrap svg {
    width: min(80vw, 360px);
    height: auto;
    color: var(--fg);
}
.caption {
    text-align: center;
    color: var(--muted);
    margin: 0 0 24px 0;
    font-size: 15px;
}
button.copy {
    display: block;
    width: 100%;
    padding: 14px;
    background: var(--accent);
    color: var(--accent-fg);
    border: 0;
    border-radius: 6px;
    font-size: 16px;
    font-weight: 500;
    cursor: pointer;
    -webkit-tap-highlight-color: transparent;
}
button.copy:active { opacity: 0.85; }
@media (min-width: 480px) {
    button.copy { width: 240px; margin: 0 auto; }
}
details {
    margin-top: 24px;
    border-top: 1px solid color-mix(in srgb, var(--fg) 12%, transparent);
    padding-top: 12px;
}
summary {
    cursor: pointer;
    color: var(--muted);
    font-size: 14px;
    padding: 8px 0;
}
.ticket-text, code.id {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    word-break: break-all;
    background: color-mix(in srgb, var(--fg) 6%, transparent);
    padding: 12px;
    border-radius: 4px;
    display: block;
    white-space: pre-wrap;
}
dl.host-details {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 8px 16px;
    font-size: 14px;
    margin: 8px 0 0 0;
}
dl.host-details dt { color: var(--muted); }
dl.host-details dd { margin: 0; word-break: break-all; }
dl.host-details code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
footer {
    margin-top: 32px;
    color: var(--muted);
    font-size: 12px;
    text-align: center;
}
.sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0;
}
</style>
</head>
<body>
<header>wires host</header>
<main>
<div class="qr-wrap" role="img" aria-label="wires host ticket QR code">__QR_SVG__</div>
<p class="caption">Scan with your wires-paired device</p>
<button class="copy" type="button" id="copy-btn">Copy ticket</button>
<textarea class="sr-only" id="ticket-hidden" readonly>__TICKET__</textarea>
<details>
<summary>Show ticket text</summary>
<code class="ticket-text">__TICKET__</code>
</details>
<details>
<summary>Host details</summary>
<dl class="host-details">
<dt>Endpoint ID</dt><dd><code class="id">__ENDPOINT_ID__</code></dd>
<dt>Issued</dt><dd><span id="issued" data-issued-ms="__ISSUED_MS__">__ISSUED_UTC__</span></dd>
<dt>TTL</dt><dd>__TTL_HUMAN__</dd>
<dt>Direct addrs</dt><dd>__ADDRS_HTML__</dd>
<dt>Relay</dt><dd>__RELAY_HTML__</dd>
</dl>
</details>
</main>
<footer>wires-host · regenerated on each request</footer>
<script>
(function () {
    var btn = document.getElementById("copy-btn");
    var hidden = document.getElementById("ticket-hidden");
    if (!btn || !hidden) return;
    btn.addEventListener("click", function () {
        var original = btn.textContent;
        var done = function (ok) {
            btn.textContent = ok ? "Copied" : "Copy failed — long-press the ticket text below";
            setTimeout(function () { btn.textContent = original; }, ok ? 1500 : 3000);
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(hidden.value).then(function () { done(true); }, function () {
                fallback(done);
            });
        } else {
            fallback(done);
        }
    });
    function fallback(done) {
        try {
            hidden.removeAttribute("hidden");
            hidden.classList.remove("sr-only");
            hidden.select();
            var ok = document.execCommand("copy");
            hidden.classList.add("sr-only");
            done(ok);
        } catch (_) {
            done(false);
        }
    }
})();
(function () {
    var el = document.getElementById("issued");
    if (!el) return;
    var ms = parseInt(el.getAttribute("data-issued-ms"), 10);
    if (!isFinite(ms)) return;
    try {
        var d = new Date(ms);
        var fmt = new Intl.DateTimeFormat(undefined, {
            dateStyle: "medium",
            timeStyle: "short"
        });
        el.textContent = fmt.format(d);
    } catch (_) {}
})();
</script>
</body>
</html>
"##;
```

- [ ] **Step 4: Add the HTML route handler**

In `crates/wires-host/src/ticket_http.rs`, add the handler after `serve_svg`:

```rust
async fn serve_html(State(state): State<Arc<AppState>>) -> Result<Response> {
    let ticket = current_ticket(&state)?;
    let body = render_page(&state, &ticket)?;
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

fn render_page(state: &AppState, ticket: &HostTicket) -> Result<String> {
    let encoded = ticket.encode().context(QrSvgSnafu)?;
    let svg_raw = ticket.render_qr_svg().context(QrSvgSnafu)?;
    let svg = svg_raw
        .replace("#1c1c1c", "currentColor")
        .replace("#ffffff", "transparent");

    let now_ms = wires_net::unix_now_ms();
    let issued_ms = now_ms;
    let issued_utc = format_iso8601_utc(issued_ms);

    let ttl_human = format_duration_human(state.hint_ttl);

    let addrs_html: String = if ticket.addrs.is_empty() {
        "<em>none</em>".to_string()
    } else {
        ticket
            .addrs
            .iter()
            .map(|a| format!("<div><code>{}</code></div>", html_escape(a)))
            .collect()
    };
    let relay_html = match &ticket.relay {
        Some(url) => format!("<code>{}</code>", html_escape(url)),
        None => "—".to_string(),
    };

    let endpoint_id_safe = html_escape(&ticket.endpoint_id);
    let ticket_safe = html_escape(&encoded);

    let page = HTML_TEMPLATE
        .replace("__QR_SVG__", &svg)
        .replace("__TICKET__", &ticket_safe)
        .replace("__ENDPOINT_ID__", &endpoint_id_safe)
        .replace("__ISSUED_MS__", &issued_ms.to_string())
        .replace("__ISSUED_UTC__", &issued_utc)
        .replace("__TTL_HUMAN__", &ttl_human)
        .replace("__ADDRS_HTML__", &addrs_html)
        .replace("__RELAY_HTML__", &relay_html);
    Ok(page)
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn format_iso8601_utc(unix_ms: i64) -> String {
    // No chrono. Convert manually to YYYY-MM-DDTHH:MM:SSZ.
    let secs = unix_ms.div_euclid(1000);
    let (y, mo, d, h, mi, s) = epoch_to_ymdhms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Convert a unix epoch seconds value to civil (Y, Mo, D, H, Mi, S) UTC.
/// Algorithm from Howard Hinnant's "chrono-Compatible Low-Level Date Algorithms"
/// (public domain).
fn epoch_to_ymdhms(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let h = (rem / 3600) as u32;
    let mi = ((rem % 3600) / 60) as u32;
    let s = (rem % 60) as u32;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

fn format_duration_human(d: Duration) -> String {
    let total = d.as_secs();
    let days = total / 86_400;
    let hours = (total % 86_400) / 3600;
    let mins = (total % 3600) / 60;
    if days > 0 {
        if hours > 0 { format!("{days}d {hours}h") } else { format!("{days}d") }
    } else if hours > 0 {
        if mins > 0 { format!("{hours}h {mins}m") } else { format!("{hours}h") }
    } else {
        format!("{mins}m")
    }
}
```

Update `build_router` to register the new route:

```rust
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(serve_html))
        .route("/ticket.txt", get(serve_txt))
        .route("/ticket.svg", get(serve_svg))
        .with_state(state)
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p wires-host --test ticket_http`
Expected: PASS.

- [ ] **Step 6: Unit-test the time + duration helpers**

Inside `crates/wires-host/src/ticket_http.rs`, append at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_handles_specials() {
        assert_eq!(html_escape("<a&b>\"'x"), "&lt;a&amp;b&gt;&quot;&#39;x");
    }

    #[test]
    fn epoch_to_ymdhms_known_dates() {
        // 2026-05-18T00:00:00Z = 1_779_062_400
        assert_eq!(epoch_to_ymdhms(1_779_062_400), (2026, 5, 18, 0, 0, 0));
        // 1970-01-01T00:00:00Z
        assert_eq!(epoch_to_ymdhms(0), (1970, 1, 1, 0, 0, 0));
        // 2000-02-29T12:34:56Z (leap day)
        assert_eq!(epoch_to_ymdhms(951_827_696), (2000, 2, 29, 12, 34, 56));
    }

    #[test]
    fn format_iso8601_utc_zero_epoch() {
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_duration_human_examples() {
        assert_eq!(format_duration_human(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration_human(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration_human(Duration::from_secs(3600 + 5 * 60)), "1h 5m");
        assert_eq!(format_duration_human(Duration::from_secs(86_400)), "1d");
        assert_eq!(format_duration_human(Duration::from_secs(7 * 86_400 - 1)), "6d 23h");
    }
}
```

Run: `cargo test -p wires-host --lib ticket_http::tests`
Expected: 4 unit tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-host/src/ticket_http.rs crates/wires-host/tests/ticket_http.rs
git commit -m "wires-host: GET / HTML ticket page"
```

---

## Phase D — Wire into the host binary

### Task 7: Add CLI flags, Ctrl+C handler, and spawn the HTTP task

**Files:**
- Modify: `crates/wires-host/src/main.rs`

- [ ] **Step 1: Add the `--http-bind` and `--no-http` flags**

Open `crates/wires-host/src/main.rs`. In the `struct Args` block (lines 25–42), add these two fields immediately after the existing `--no-qr` field (around line 38):

```rust
    /// Bind address for the ticket HTTP page.
    #[arg(long, global = true, default_value = "0.0.0.0:8089", conflicts_with = "no_http")]
    http_bind: std::net::SocketAddr,

    /// Disable the ticket HTTP page entirely.
    #[arg(long, global = true)]
    no_http: bool,
```

- [ ] **Step 2: Add the imports**

Near the top of `crates/wires-host/src/main.rs` (alongside the other `use` lines), add:

```rust
use tokio_util::sync::CancellationToken;
use wires_host::ticket_http;
```

- [ ] **Step 3: Replace the run loop with a CancellationToken-driven version**

In `crates/wires-host/src/main.rs`, the current end of `main` looks like this (around lines 186–194):

```rust
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip_handler)
        .accept(REPLAY_ALPN, replay_protocol)
        .accept(TENANT_ALPN, TenantProtocol::new(Arc::clone(&handler)))
        .spawn();

    println!("wires-host: running. Press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

Replace it with:

```rust
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip_handler)
        .accept(REPLAY_ALPN, replay_protocol)
        .accept(TENANT_ALPN, TenantProtocol::new(Arc::clone(&handler)))
        .spawn();

    // Shared shutdown signal. Ctrl+C cancels the token; the HTTP task and
    // any future tasks observe it via `shutdown.cancelled().await`.
    let shutdown = CancellationToken::new();
    {
        let s = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            s.cancel();
        });
    }

    let http_handle = if !args.no_http {
        let (bound, handle) = ticket_http::spawn(
            endpoint.clone(),
            args.http_bind,
            *args.ticket_hint_ttl,
            shutdown.clone(),
        )
        .await?;
        tracing::info!("ticket-http listening on http://{bound}/");
        Some(handle)
    } else {
        None
    };

    println!("wires-host: running. Press Ctrl-C to exit.");
    shutdown.cancelled().await;

    if let Some(h) = http_handle {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "ticket-http exited with error"),
            Err(e) => tracing::error!(error = %e, "ticket-http task panicked"),
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Verify the host still builds and starts**

Run: `cargo build -p wires-host`
Expected: builds clean.

Then a smoke test — start the host in the background, GET the page, kill it:

```bash
TMP=$(mktemp -d)
cargo run -p wires-host --quiet -- --data-dir "$TMP" --no-qr --http-bind 127.0.0.1:0 &
HOST_PID=$!
# Give iroh time to warm up and bind. The actual bound port is logged via
# tracing::info!, but for this smoke test grab anything that's listening on
# loopback ≥1024 owned by our PID. On macOS:
sleep 8
PORT=$(lsof -nP -p $HOST_PID -iTCP -sTCP:LISTEN 2>/dev/null | awk '/127\.0\.0\.1/ {split($9,a,":"); print a[2]; exit}')
echo "host listening on 127.0.0.1:$PORT"
curl -s "http://127.0.0.1:$PORT/ticket.txt" | head -c 60 && echo
kill $HOST_PID 2>/dev/null
wait $HOST_PID 2>/dev/null
rm -rf "$TMP"
```

Expected: a base64 string prints (60 chars truncated), then host exits cleanly. If `lsof` is unavailable substitute the platform equivalent (`ss -tlnp` on Linux); the goal is just to confirm a port is bound.

- [ ] **Step 5: Confirm `--no-http` disables the server**

```bash
TMP=$(mktemp -d)
cargo run -p wires-host --quiet -- --data-dir "$TMP" --no-qr --no-http &
HOST_PID=$!
sleep 6
# There should be no listener on 8089 owned by this PID.
LISTENING=$(lsof -nP -p $HOST_PID -iTCP -sTCP:LISTEN 2>/dev/null | awk '/127\.0\.0\.1|0\.0\.0\.0/ {print $9}')
echo "listeners: $LISTENING"
# Expected: only iroh's own UDP/TCP, no 8089.
kill $HOST_PID 2>/dev/null
wait $HOST_PID 2>/dev/null
rm -rf "$TMP"
```

Expected: no listener on TCP `:8089` is observed.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-host/src/main.rs
git commit -m "wires-host: --http-bind/--no-http flags + Ctrl+C-driven shutdown"
```

---

## Phase E — Verification

### Task 8: Workspace-wide checks

**Files:** none (verification only).

- [ ] **Step 1: Workspace build**

Run: `cargo build --workspace`
Expected: builds clean.

- [ ] **Step 2: Workspace lib tests**

Run: `cargo test --workspace --lib`
Expected: all pass. (If the first run hits an iroh cold-start failure on `wires-net::tenant::tests::topic_register_status_unregister_helpers_round_trip`, retry once — documented in CLAUDE.md.)

- [ ] **Step 3: Workspace integration tests**

Run: `cargo test --workspace --tests`
Expected: all pass, including the new `wires-host::ticket_http` integration test.

- [ ] **Step 4: Clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: zero warnings. Likely tidy-ups: unused imports, `&Arc<X>` instead of `&X`, etc. Fix in-place; no new behavior.

- [ ] **Step 5: Rustfmt**

Run: `cargo fmt --all`
Expected: idempotent, no diff. If it produced a diff, commit it as a separate `chore: rustfmt` commit.

- [ ] **Step 6: Manual smoke (optional, gated on access to a phone on the same LAN)**

Start the host:

```bash
cargo run -p wires-host -- --data-dir /tmp/wires-host-demo --no-qr
```

Note the line `ticket-http listening on http://0.0.0.0:8089/`. From a phone on the same LAN, browse to `http://<box-lan-ip>:8089/`. Verify:

- The QR is visible, square, and scannable by a generic QR scanner app.
- The "Copy ticket" button copies a long base64 string to the clipboard.
- "Show ticket text" reveals the base64 in a monospace block.
- "Host details" shows a hex endpoint id, an "Issued" line in local time (not UTC), a TTL like "7d", and at least one direct addr.
- Reloading the page is fine; the QR shifts pixels but remains scannable.

- [ ] **Step 7: Final commit (only if there's a fmt/clippy fix to land)**

```bash
git add -u
git commit -m "chore: clippy/fmt cleanup for ticket-http"
```

---

## Notes for the implementer

- `wires-net::HostTicket` and its `from_endpoint` / `encode` / `render_qr_svg` (added in Task 1) are the only wires-net touch-points. No wire-format changes anywhere.
- The HTTP module is intentionally a leaf: it depends on `wires-net` (already on the crate's dependency list) and on `axum` + `tokio-util` (new). It does not reach into `tenant_registry`, `routing`, `retention`, or any other host module.
- The integration test pays one iroh cold-start. If you find yourself running it in a tight loop, set `RUST_TEST_THREADS=1` and prefer running by name (`cargo test -p wires-host --test ticket_http ticket_http_serves_all_three_routes`).
- The HTML template is held verbatim in a single `&str` const. If a future iteration wants to externalize it (askama, minijinja), the seam is small — every interpolation is a `__SCREAMING_PLACEHOLDER__` — but YAGNI for v1.
- Do not add a `/health` or `/metrics` route in this plan. The spec puts those out of scope.
