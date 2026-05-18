use axum::response::Html;
use crate::oauth::authorize::AuthorizeContext;

pub fn render(ctx: &AuthorizeContext) -> Html<String> {
    Html(format!(
        "<!doctype html><html><body><p>session: {}</p></body></html>",
        ctx.session_id
    ))
}
