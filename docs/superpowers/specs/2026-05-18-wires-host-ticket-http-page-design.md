# wires — host-ticket HTTP page

**Status:** design, 2026-05-18. Adds a tiny always-on HTTP surface to `wires-host` that serves the host's `HostTicket` as a QR-first web page, plus two raw routes for scripting and embedding. Companion to the host-ticket-discovery spec (2026-05-15); does not change the ticket format or any wire protocol.

## 1. Motivation

Today, `wires-host` exposes its `HostTicket` in two places:

- **Startup log line** — base64 to `tracing::info!`, plus an ANSI-block QR to stderr when stderr is a TTY (`wires-host/src/main.rs` lines 80–93).
- **`wires-host ticket` subcommand** — one-shot print to stdout/stderr.

Both assume the operator has a shell on the box. In practice `wires-host` runs headless on a homelab box, NAS, or VPS, and the operator's nearest device for capturing a QR is a phone — specifically the iOS companion, which is designed to scan one on first launch (iOS companion spec §3, currently being revised to match this surface).

A user opening `http://<host>.local:8089/` on their phone and scanning the QR — or copying the base64 with one tap — is the canonical path. Today they have to `ssh` in and copy a string out of a terminal, or run `wires-host ticket` over SSH and screenshot a Unicode block. Both work and both are friction the project is trying to delete.

This spec adds a minimal HTTP surface to `wires-host` that serves the same `HostTicket` as a mobile-friendly web page. The page is one route plus two raw companion routes (`.txt`, `.svg`), no external assets, no JavaScript framework, no auth. The ticket is not a secret (it's discovery info plus a public `EndpointId`); the pairing handshake remains the security boundary.

## 2. Scope of change

**Added:**

- `wires-host/src/ticket_http.rs` — new module. `spawn(endpoint, bind, ttl, cancellation) -> Result<JoinHandle<()>>`. Hosts the axum `Router` and serves until cancelled.
- `wires-net::ticket::HostTicket::render_qr_svg(&self) -> Result<String>` — peer of the existing `render_qr_ansi`. Uses the already-present `qrcode = "0.14"` dep.
- `axum = "0.8"` dep on `wires-host`, default-features only (`http1`, `tokio`, `query`, `matched-path` — drop `tower-http` extras, drop `macros`).
- `reqwest = { version = "0.12", default-features = false, features = ["blocking", "rustls-tls"] }` as a **dev-dep** on `wires-host` for the integration test. Not on the main build.
- New CLI flags on the `wires-host` binary:
  - `--http-bind <SOCKETADDR>` — global flag, default `0.0.0.0:8089`.
  - `--no-http` — global flag, disables the HTTP server entirely. Conflicts with `--http-bind`.
- New `HostError` variants for HTTP bind/serve failures and QR SVG rendering, following the existing snafu pattern.

**Changed:**

- `wires-host/src/main.rs` — after `endpoint` is bound and before the tenant/replay routers spawn, conditionally spawns the HTTP task. Plumbs a `tokio_util::sync::CancellationToken` (or the existing shutdown signal, if one is already in place) so graceful shutdown drains in-flight requests.
- `wires-host/src/error.rs` — three new variants (`HttpBind`, `HttpServe`, `QrSvg`), following the established snafu shape (`#[snafu(implicit)] location`, no `message:` field, display ending in `, at {location}`).

**Unchanged:**

- `HostTicket` wire format. The QR/base64 served by the page is byte-identical to what `wires-host ticket` and the startup log line emit.
- The `wires-host ticket` subcommand. Still works exactly as before.
- The startup-time log line + ANSI QR emission. Still happens. The HTTP page is additive.
- Tenant control protocol, replay protocol, pairing protocol, retention, eviction, routing. The HTTP surface is a leaf and touches none of these.
- Crate layering. `wires-host` already depends on `wires-net`; the new SVG render lives in `wires-net::ticket` alongside `render_qr_ansi`.
- Trust model and host-blindness contract. The HTTP surface has no caps, no decryption, no per-tenant state; it sees the same public `HostTicket` anyone on the LAN can scan off a stranger's screen.

## 3. HTTP surface

Three routes, served on `--http-bind` (default `0.0.0.0:8089`).

| Method | Path | Content-Type | Body |
|---|---|---|---|
| GET | `/` | `text/html; charset=utf-8` | The page described in §4. |
| GET | `/ticket.txt` | `text/plain; charset=utf-8` | The base64 ticket, one line, no trailing newline. |
| GET | `/ticket.svg` | `image/svg+xml` | The QR rendered as standalone SVG. |

All three responses carry `Cache-Control: no-store`.

All three handlers rebuild the ticket on every request via `HostTicket::from_endpoint(&endpoint, ttl)`. The semantically meaningful fields (`endpoint_id`, `addrs`, `relay`, `ttl`) are stable across calls; `issued_at` advances. The encoded base64 (and therefore the QR pixels) differ on each render. Consumers don't care: any ticket whose `issued_at + ttl` window has not passed is fresh, and a scan succeeds regardless. The freshness cost of building per-request is sub-millisecond.

No other routes — no `/health`, no `/metrics`, no `/index.json`. A bare GET on any other path returns axum's default `404`. Methods other than `GET` return `405`.

## 4. The page (`GET /`)

Single self-contained HTML document. Inline `<style>` and inline `<script>`. No external CSS, no external JS, no external fonts, no images beyond the inline SVG QR. The whole document is well under 10 KB.

### 4.1 Structure

```
<header>      "wires host" — small monospace label, faint
<main>
  <svg>       The QR. Square, centered, max-width: min(80vw, 360px).
              aria-label="wires host ticket QR code".
  <p>         Caption: "Scan with your wires-paired device".
  <button>    "Copy ticket" — full-width on mobile, ≥44px tall.
  <details>   <summary>Show ticket text</summary>
              <code>…base64…</code>     (monospace, word-broken)
  <details>   <summary>Host details</summary>
              <dl>
                Endpoint ID    full 64-hex, monospace, word-broken
                Issued         ISO 8601, rendered to local time by inline JS
                TTL            humantime-style ("6d 23h")
                Direct addrs   one per <li>
                Relay          url or "—"
              </dl>
<footer>      "wires-host · regenerated on each request" — small, faint
```

The base64 ticket is rendered into a hidden `<textarea>` (or `<span hidden>`) at page load so the copy script never has to fetch it. The visible `<details>` block also contains the base64, so a user without clipboard access can long-press and copy.

### 4.2 Styling

System font stack for prose:

```css
font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
```

Monospace for ticket text and IDs:

```css
font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
```

Single accent color used only on the copy button: `#3b6ea8` (a desaturated mid-blue). All other UI is neutral grays.

Light mode default; dark mode via `@media (prefers-color-scheme: dark)`:
- Light: background `#fafafa`, text `#1c1c1c`, muted text `#666`.
- Dark: background `#0e0e10`, text `#eaeaea`, muted text `#999`.

Generous whitespace. Body has `padding: 24px`, `max-width: 480px`, `margin: 0 auto`. QR is centered. Section spacing is 24–32px between blocks. No box shadows, no rounded-corner cards, no gradients.

The button is the only interactive ornament: full-width on screens narrower than 480px, fixed-width (240px) above that, with `padding: 12px`, accent background, white text, no border. `:active` state darkens by ~10%. No hover state on touch.

Native `<details>/<summary>` disclosure — no custom JS for expand/collapse. The default triangle marker is fine; `summary { cursor: pointer }`.

### 4.3 Script

Two scripts, both inline, total ~30 lines:

1. **Copy button** (~15 lines): on click, calls `navigator.clipboard.writeText(ticket)`. On success swaps button text to "Copied" for 1.5s then restores. On failure (insecure context, old browser), falls back to selecting the hidden `<textarea>` and `document.execCommand('copy')`. If both fail, swaps button text to "Copy failed — long-press the ticket text below" for 3s.
2. **Local-time render** (~10 lines): the "Issued" field is rendered server-side in ISO 8601 UTC. The inline script reads `data-issued-ms` from that element and rewrites it to a locale-formatted string via `Intl.DateTimeFormat`. If JS is disabled, the UTC ISO timestamp remains visible — still useful, just less friendly.

No other JS. No event listeners on anything else. No fetch calls. The page does not refresh itself; reloading is a user action.

### 4.4 Accessibility

- The copy button is a real `<button>`, focusable, Enter/Space activate.
- `<details>/<summary>` is native disclosure — keyboard and screen-reader ready.
- The QR `<svg>` has `role="img"` and `aria-label="wires host ticket QR code"`.
- Color contrast meets WCAG AA in both light and dark modes.
- Tap targets are ≥44px tall.

### 4.5 Security headers

No CSP for v1. The page is `self`-only and inline-only; on a LAN box the configuration overhead isn't justified by the threat model. Easy to add later if the surface grows.

`Cache-Control: no-store` on all three routes (the ticket changes every request).

No CORS headers. Browsers may treat the routes as same-origin only; for the iOS app's native scanner this is irrelevant — it doesn't go through the browser.

## 5. `wires-net::ticket::render_qr_svg`

Mirror of the existing `render_qr_ansi` in the same file:

```rust
impl HostTicket {
    pub fn render_qr_svg(&self) -> Result<String> {
        let s = self.encode()?;
        let code = qrcode::QrCode::new(s.as_bytes()).context(QrEncodeSnafu)?;
        let svg = code
            .render::<qrcode::render::svg::Color>()
            .quiet_zone(true)
            .dark_color(qrcode::render::svg::Color("#1c1c1c"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build();
        Ok(svg)
    }
}
```

The colors are baked in for the `/ticket.svg` route because raw SVG has no surrounding CSS to inherit from. The HTML page inlines a second, page-styled copy of the SVG: it calls `render_qr_svg`, then does a single `str::replace("#1c1c1c", "currentColor")` and a `str::replace("#ffffff", "transparent")` on the result before injecting it. With those replacements the QR inherits the page's text color through `currentColor`, so light mode renders dark-on-light and dark mode renders light-on-dark automatically without a media query. Scannable in both.

A new error variant on `NetError` (`QrEncode { source: qrcode::types::QrError, location }`) covers the failure case. Encoding a HostTicket (a couple hundred bytes) into a QR cannot exceed the QR version limit; the error path is theoretical but the snafu shape is required by the project convention.

## 6. CLI flags and defaults

```
wires-host [GLOBAL FLAGS]

  --http-bind <SOCKETADDR>     default 0.0.0.0:8089
  --no-http                    disable the HTTP server (conflicts with --http-bind)
```

Both flags are global, like the existing `--qr` / `--no-qr` pair. They apply to the long-running server form; the `wires-host ticket` subcommand ignores them (it's a one-shot print, never serves HTTP).

Port choice: `8089` is unassigned by IANA, unlikely to collide with other local services, easy to remember (one off from `8088` / `8090` which see common dev use). Operators who want a different port use `--http-bind`.

## 7. Lifecycle and wiring

In `wires-host/src/main.rs`, after the endpoint is bound (line ~75) and before the tenant/replay routers are spawned:

```rust
let http_handle = if !args.no_http {
    Some(ticket_http::spawn(
        endpoint.clone(),
        args.http_bind,
        *args.ticket_hint_ttl,
        shutdown_token.clone(),
    ).await?)
} else {
    None
};
```

The `shutdown_token` is a `tokio_util::sync::CancellationToken`. The current `main.rs` does not have one; this spec adds it. The wiring is small: at the top of `main`, after parsing args, create `let shutdown = CancellationToken::new();` and spawn `tokio::spawn({ let s = shutdown.clone(); async move { let _ = tokio::signal::ctrl_c().await; s.cancel(); }});`. The HTTP task takes a clone; future tasks (replay router shutdown, tenant router shutdown) can take clones as the host's lifecycle story matures. `tokio_util` is added as a dep alongside `axum` (already pulled transitively by axum's `tower` integration; needs the `sync` feature explicitly).

`ticket_http::spawn` does:

1. `tokio::net::TcpListener::bind(args.http_bind).await.context(HttpBindSnafu)?` — fail fast on EADDRINUSE, log a clear error.
2. Log `tracing::info!("ticket-http listening on http://{bound_addr}/")`. If bound to `0.0.0.0`, additionally log a hint with the host's first non-loopback IPv4 so operators see a copy-pasteable URL.
3. Build the `axum::Router` with the three routes; shared state is `Arc<(Endpoint, Duration)>`.
4. `axum::serve(listener, router).with_graceful_shutdown(shutdown_token.cancelled_owned()).await.context(HttpServeSnafu)`.
5. Return the `JoinHandle<()>` to `main`. `main` awaits all task handles before exiting.

`HostError` gains three variants, each following the established snafu shape (every variant has `#[snafu(implicit)] location: Location`, no `message:` field, display ending in `, at {location}`):

```rust
#[snafu(display("bind ticket-http on {bind}: {source}, at {location}"))]
HttpBind { bind: SocketAddr, source: std::io::Error, #[snafu(implicit)] location: Location },

#[snafu(display("serve ticket-http: {source}, at {location}"))]
HttpServe { source: std::io::Error, #[snafu(implicit)] location: Location },

#[snafu(display("render QR SVG: {source}, at {location}"))]
QrSvg { source: wires_net::NetError, #[snafu(implicit)] location: Location },
```

## 8. Testing

### 8.1 Unit — `wires-net/src/ticket.rs`

`render_qr_svg_produces_svg`: build a sample ticket, call `render_qr_svg`, assert the output starts with `<?xml` or `<svg`, contains at least one `<rect` or `<path`, and is non-trivially sized (>1 KB). Mirrors `render_qr_ansi_produces_block_art`.

### 8.2 Integration — `wires-host/tests/ticket_http.rs` (new)

Single test file, three test functions, sharing a small `spawn_host_for_test` helper that:

- Uses a `tempfile::TempDir` for `data_dir`.
- Generates a fresh iroh secret via `rand_core::OsRng`.
- Binds the host's iroh endpoint via `bind_lan` with a 10-second `endpoint.online()` timeout (matching the defensive pattern documented in the project CLAUDE.md for cold-start flakiness).
- Spawns `ticket_http::spawn(...)` on `127.0.0.1:0`. `spawn` is adjusted to expose the bound address back to the caller — the test reads it before issuing requests, so port 0 works.
- Returns `(bound_addr, endpoint_id_hex, shutdown_token, join_handle)`.

The three test functions:

1. **`ticket_txt_decodes_to_host_endpoint`** — `GET /ticket.txt` via `reqwest::blocking::Client`, body trimmed, `HostTicket::decode(body)` succeeds and `endpoint_id` matches the host's endpoint id.
2. **`ticket_svg_is_svg`** — `GET /ticket.svg`, content-type starts with `image/svg+xml`, body starts with `<?xml` or `<svg`.
3. **`index_html_contains_ticket_and_caption`** — `GET /`, content-type starts with `text/html`, body contains the base64 ticket string (or its first 32 chars, since rebuilding per-request means the exact string between the GET above and this GET will differ on `issued_at` but the structure is the same — assert on the visible caption "Scan with" and on the regex `<svg[\s>]`).

Each test asserts `Cache-Control: no-store` is present.

No iroh relay or gossip traffic participates in these tests, but `bind_lan` does need to come online, so a cold-machine first run pays the documented 5–30s iroh warm-up (project CLAUDE.md, "cold-start flakiness"). The HTTP portion itself adds well under 100ms.

### 8.3 Manual

A short note in the spec is enough — the maintainer cuts a release, runs `wires-host --data-dir /tmp/h`, opens `http://localhost:8089/` and `http://<lan-ip>:8089/` from a phone, scans the QR with the iOS companion (once it's wired up), and verifies the iOS app accepts the ticket.

## 9. Out of scope

- **Auth on the HTTP surface.** The ticket is not a secret. LAN binding + the existing trust model are sufficient for v1. If a future deployment scenario (multi-tenant SaaS host? bastion-fronted private host?) wants auth, it slots in as a `tower` middleware layer without changing routes or page.
- **TLS.** Same reasoning. Operators who want HTTPS run the host behind a reverse proxy of their choice.
- **Auto-refresh / SSE / WebSocket live updates.** The ticket payload is stable enough that "reload to refresh" is fine. SSE would also require keeping a TCP connection open per phone in the room, which is more state than the surface deserves.
- **Multi-host views, host management UI.** Out of scope; this is a single-host artifact page.
- **mDNS advertisement of the HTTP service.** The iroh endpoint already advertises itself via the `mdns` feature in `wires-net`; a separate `_wires-ticket._tcp` record could be added later if discovery without a known hostname becomes a friction point. For now, operators visit `http://<box>.local:8089/` or the LAN IP they already know.
- **A second iOS-companion-facing surface (e.g., live pair-listen mirroring).** This spec is strictly about the host ticket. Anything the iOS app needs after scanning the QR (pair-listen, capability mint, topic subscription) happens over iroh, not HTTP.

## 10. Migration notes

None for runtime data. The new HTTP server is additive: existing operators see one extra log line at startup (`ticket-http listening on http://0.0.0.0:8089/`) and one extra listening socket. Existing CLI behavior is unchanged. Existing tickets are unchanged in format and remain interoperable.

Operators who need to suppress the new server (port collision, security policy) add `--no-http` to their `wires-host` invocation.
