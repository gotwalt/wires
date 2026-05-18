//! End-to-end acceptance: drive a full /authorize → pair → token → publish
//! → tail round-trip against an in-process gateway. Marked #[ignore] because
//! it runs real iroh endpoints and currently relies on a `pair-approve`
//! helper that has not yet been factored out of wires-cli.
//!
//! Skeleton commits supporting API touchpoints (`http::serve_with_listener`,
//! consent-page meta tags carrying session_id / pair_token / signin_challenge).
//!
//! Implementer steps (filled in by follow-up):
//!
//!   1. Spawn `http::serve_with_listener` on a `TcpListener::bind("127.0.0.1:0")`.
//!   2. POST /oauth/register with `{"client_name":"acceptance","redirect_uris":["http://localhost/cb"]}`.
//!   3. GET /oauth/authorize?... and parse the rendered HTML to extract
//!      `<meta name="wires-mcp-pair-token" content="...">`.
//!   4. Decode the PairRequest token; mint a Capability for the gateway-agent
//!      against a fresh root SigningKey + topic; build a PairGrant; seal +
//!      sign; dial /wires/pair/0 via `wires_net::pair::PairClient`; await Ack.
//!   5. Poll /oauth/authorize/status/{session_id} until `done`; extract `code`.
//!   6. POST /oauth/token with PKCE verifier; receive access token.
//!   7. POST /mcp `tools/call wires.publish`; assert success.
//!   8. POST /mcp `tools/call wires.tail`; assert the published message comes
//!      back in the messages array.
//!
//! The fake-iOS cap-mint + PairGrant assembly mirrors what
//! `wires-cli::cmd::pair_approve::run` does (193 LOC). When the project
//! factors that helper into a reusable location (e.g. a `wires-pair-test`
//! support crate or a `wires-node::pair::approver` helper), update this
//! test to use it.

#[tokio::test]
#[ignore]
async fn first_time_pair_then_publish_then_tail() {
    panic!(
        "End-to-end acceptance test skeleton. \
         Fill in per the steps in this file's module doc comment. \
         The supporting API touchpoints (serve_with_listener + consent-page meta tags) \
         are already in place."
    );
}
