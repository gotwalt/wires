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

use crate::error::{HostError, HostTicketSnafu, HttpBindSnafu, HttpServeSnafu, Result};

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

struct AppState {
    endpoint: iroh::Endpoint,
    hint_ttl: Duration,
    server_name: Option<String>,
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
    server_name: Option<String>,
    shutdown: CancellationToken,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(bind)
        .await
        .context(HttpBindSnafu { bind })?;
    let bound = listener.local_addr().context(HttpBindSnafu { bind })?;
    let state = Arc::new(AppState {
        endpoint,
        hint_ttl,
        server_name,
    });
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
        .route("/", get(serve_html))
        .route("/ticket.txt", get(serve_txt))
        .route("/ticket.svg", get(serve_svg))
        .with_state(state)
}

/// Build the current ticket from the live endpoint. Re-derived per request.
fn current_ticket(state: &AppState) -> Result<HostTicket> {
    HostTicket::from_endpoint(&state.endpoint, state.hint_ttl, state.server_name.clone())
        .context(HostTicketSnafu)
}

async fn serve_txt(State(state): State<Arc<AppState>>) -> Result<Response> {
    let ticket = current_ticket(&state)?;
    let body = ticket.encode().context(HostTicketSnafu)?;
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

async fn serve_svg(State(state): State<Arc<AppState>>) -> Result<Response> {
    let ticket = current_ticket(&state)?;
    let svg = ticket.render_qr_svg().context(HostTicketSnafu)?;
    let mut resp = svg.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

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
    let encoded = ticket.encode().context(HostTicketSnafu)?;
    let svg_raw = ticket.render_qr_svg().context(HostTicketSnafu)?;
    // Replace raw color literals in the SVG so it uses CSS currentColor for
    // dark-mode compatibility. The HTML template's CSS hex literals are left intact.
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
        if hours > 0 {
            format!("{days}d {hours}h")
        } else {
            format!("{days}d")
        }
    } else if hours > 0 {
        if mins > 0 {
            format!("{hours}h {mins}m")
        } else {
            format!("{hours}h")
        }
    } else {
        format!("{mins}m")
    }
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
        assert_eq!(
            format_duration_human(Duration::from_secs(3600 + 5 * 60)),
            "1h 5m"
        );
        assert_eq!(format_duration_human(Duration::from_secs(86_400)), "1d");
        assert_eq!(
            format_duration_human(Duration::from_secs(7 * 86_400 - 1)),
            "6d 23h"
        );
    }
}
