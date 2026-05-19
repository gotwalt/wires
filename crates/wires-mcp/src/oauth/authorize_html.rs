//! Renders the consent HTML page. A single QR (the `SessionTicket`) is shown
//! inline as SVG. A small JS polling loop hits
//! `/oauth/authorize/status/<session_id>` and performs the OAuth redirect when
//! either the pair or sign-in path completes.

use axum::response::Html;

use crate::oauth::authorize::AuthorizeContext;

pub fn render(ctx: &AuthorizeContext) -> Html<String> {
    let qr_svg = render_qr_svg(&ctx.session_ticket_b64);
    let session_id = html_escape(&ctx.session_id);
    let client_name = html_escape(&ctx.client_name);
    Html(format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in to MCP Gateway</title>
<meta name="wires-mcp-session-id" content="{session_id}">
<meta name="wires-mcp-session-ticket" content="{ticket_b64}">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; max-width: 520px; }}
h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
.subtitle {{ color: #666; margin-top: 0; }}
.card {{ margin-top: 2rem; border: 1px solid #ddd; border-radius: 12px; padding: 1.5rem; text-align: center; }}
.qr {{ width: 280px; height: 280px; margin: 0 auto; }}
.qr svg {{ width: 100%; height: 100%; }}
.hint {{ color: #666; font-size: 0.95rem; margin-top: 1rem; }}
</style>
</head>
<body>
<h1>Sign in to MCP Gateway</h1>
<p class="subtitle">Requesting access for <strong>{client_name}</strong>. Scope: <code>mcp:wires</code>.</p>
<div class="card">
  <div class="qr">{qr_svg}</div>
  <p class="hint">Open the Wires app on your iPhone and scan this code. Whether this is a new account or you've signed in before, the app will figure it out.</p>
</div>
<p id="status" class="hint">Waiting…</p>
<script>
(async () => {{
  const sid = {session_id_json};
  while (true) {{
    const r = await fetch('/oauth/authorize/status/' + encodeURIComponent(sid));
    if (!r.ok) {{ document.getElementById('status').textContent = 'status error'; break; }}
    const body = await r.json();
    if (body.kind === 'done') {{
      const u = new URL(body.redirect_uri);
      u.searchParams.set('code', body.code);
      u.searchParams.set('state', body.state);
      window.location = u.toString();
      return;
    }} else if (body.kind === 'expired') {{
      document.getElementById('status').textContent = 'session expired, reload to try again';
      return;
    }}
    await new Promise(r => setTimeout(r, 1500));
  }}
}})();
</script>
</body></html>"##,
        session_id_json = serde_json::to_string(&session_id).unwrap(),
        ticket_b64 = html_escape(&ctx.session_ticket_b64),
    ))
}

fn render_qr_svg(payload: &str) -> String {
    if payload.is_empty() {
        return "<svg viewBox=\"0 0 1 1\"></svg>".to_string();
    }
    match qrcode::QrCode::new(payload.as_bytes()) {
        Ok(qr) => qr.render::<qrcode::render::svg::Color>().build(),
        Err(_) => "<svg viewBox=\"0 0 1 1\"></svg>".to_string(),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_single_qr_and_session_id() {
        let ctx = AuthorizeContext {
            session_id: "sess-1".into(),
            client_name: "Claude Desktop".into(),
            session_ticket_b64: "AAAA".into(),
        };
        let html = render(&ctx).0;
        assert!(html.contains("sess-1"));
        assert!(html.contains("Claude Desktop"));
        // Single QR now (was 2).
        assert_eq!(html.matches("<svg").count(), 1);
        // Meta tag matches the new name.
        assert!(html.contains("wires-mcp-session-ticket"));
        assert!(!html.contains("wires-mcp-pair-token"));
    }

    #[test]
    fn renders_safely_with_html_in_client_name() {
        let ctx = AuthorizeContext {
            session_id: "sess-1".into(),
            client_name: "<script>evil</script>".into(),
            session_ticket_b64: "AAAA".into(),
        };
        let html = render(&ctx).0;
        assert!(!html.contains("<script>evil"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
