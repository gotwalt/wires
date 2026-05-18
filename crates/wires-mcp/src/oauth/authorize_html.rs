//! Renders the consent HTML page. Two QR codes (pair on the left, sign-in
//! on the right) inline as SVG, plus a small JS polling loop that hits
//! `/oauth/authorize/status/<session_id>` and performs the OAuth redirect
//! when one of the paths completes.

use axum::response::Html;

use crate::oauth::authorize::AuthorizeContext;

pub fn render(ctx: &AuthorizeContext) -> Html<String> {
    let pair_svg = render_qr_svg(&ctx.pair_token_b64);
    let signin_svg = render_qr_svg(&ctx.signin_challenge_b64);
    let session_id = html_escape(&ctx.session_id);
    let client_name = html_escape(&ctx.client_name);
    Html(format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in to MCP Gateway</title>
<meta name="wires-mcp-session-id" content="{session_id}">
<meta name="wires-mcp-pair-token" content="{pair_token_b64}">
<meta name="wires-mcp-signin-challenge" content="{signin_challenge_b64}">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; max-width: 860px; }}
h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
.subtitle {{ color: #666; margin-top: 0; }}
.row {{ display: flex; gap: 2rem; margin-top: 2rem; }}
.col {{ flex: 1; border: 1px solid #ddd; border-radius: 12px; padding: 1.5rem; text-align: center; }}
.col h2 {{ font-size: 1.1rem; margin: 0 0 1rem; }}
.qr {{ width: 240px; height: 240px; margin: 0 auto; }}
.qr svg {{ width: 100%; height: 100%; }}
.hint {{ color: #666; font-size: 0.9rem; margin-top: 1rem; }}
</style>
</head>
<body>
<h1>Sign in to MCP Gateway</h1>
<p class="subtitle">Requesting access for <strong>{client_name}</strong>. Scope: <code>mcp:wires</code>.</p>
<div class="row">
  <div class="col">
    <h2>First time here?</h2>
    <div class="qr">{pair_svg}</div>
    <p class="hint">Scan with the Wires app and approve the new agent.</p>
  </div>
  <div class="col">
    <h2>Already signed in?</h2>
    <div class="qr">{signin_svg}</div>
    <p class="hint">Scan with the Wires app to authenticate.</p>
  </div>
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
        pair_token_b64 = html_escape(&ctx.pair_token_b64),
        signin_challenge_b64 = html_escape(&ctx.signin_challenge_b64),
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
    fn render_includes_both_qrs_and_session_id() {
        let ctx = AuthorizeContext {
            session_id: "sess-1".into(),
            client_name: "Claude Desktop".into(),
            pair_token_b64: "AAAA".into(),
            signin_challenge_b64: "BBBB".into(),
        };
        let html = render(&ctx).0;
        assert!(html.contains("sess-1"));
        assert!(html.contains("Claude Desktop"));
        // Two SVGs (one per QR).
        assert_eq!(html.matches("<svg").count(), 2);
    }

    #[test]
    fn renders_safely_with_html_in_client_name() {
        let ctx = AuthorizeContext {
            session_id: "sess-1".into(),
            client_name: "<script>evil</script>".into(),
            pair_token_b64: "AAAA".into(),
            signin_challenge_b64: "BBBB".into(),
        };
        let html = render(&ctx).0;
        assert!(!html.contains("<script>evil"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
