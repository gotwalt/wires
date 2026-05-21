# wires-mcp gateway

`wires-mcp` exposes a small authenticated MCP surface so AI-agent
clients (Claude Desktop, Cursor, VS Code, etc.) can act on a fabric's
behalf. It pairs into each fabric as a normal wires agent — and
`wires-host`'s blindness contract is unchanged.

The gateway is multi-fabric: one `wires-mcp` instance serves many
fabrics, with one OAuth-bound user per fabric root. Each user has a
private `users/<root>/` data dir and an isolated `NodeRuntime`. Per-user
retention (TTL + byte budget; defaults 1 h / 50 MiB) keeps the
gateway's disk footprint bounded without coordinating with the host.

Spec: [`mcp-gateway-design`](superpowers/specs/2026-05-18-wires-mcp-gateway-design.md).
Retention: [`mcp-retention-design`](superpowers/specs/2026-05-18-wires-mcp-retention-design.md).
For the four-terminal substrate walkthrough that the gateway sits on
top of, see [`quickstart.md`](quickstart.md).

## Operator walkthrough (running directly)

```bash
# 1. Generate a config.
cat >/etc/wires-mcp/config.toml <<EOF
public_url = "https://mcp.example.com"
bind = "127.0.0.1:3001"
data_dir = "/var/lib/wires-mcp"

# Optional. Defaults: ttl_secs = 3600 (1 h), max_bytes_per_user = 52428800 (50 MiB).
# ttl_secs must be > 0; max_bytes_per_user = 0 disables the byte cap.
# [retention]
# ttl_secs = 3600
# max_bytes_per_user = 52428800
EOF

# 2. Run the service.
wires-mcp serve

# 3. List onboarded users.
wires-mcp user-list

# 4. Remove a user (e.g. fabric-side cap was revoked).
wires-mcp user-delete <root_pubkey_hex>
```

Operators must put a TLS-terminating reverse proxy (nginx, caddy, etc.)
in front of `wires-mcp`; the binary speaks plain HTTP and assumes a
trusted upstream for TLS.

## Operator walkthrough (Docker + Tailscale Funnel)

> **Temporary.** This Docker + Funnel setup is a placeholder so we can
> dogfood the gateway against a real public HTTPS URL. The eventual
> alpha hosting story hasn't been chosen yet — expect this section to
> be replaced.

The current reference deploy packages `wires-host` and `wires-mcp` as
a two-service Docker Compose stack with Tailscale Funnel providing
public HTTPS. See [`docker/README.md`](../docker/README.md) for the
full runbook; the short version:

```bash
# One-time per host: seed the wires-mcp config (edit public_url).
cp docker/wires-mcp.toml.example docker/wires-mcp.toml
${EDITOR:-nano} docker/wires-mcp.toml

# Build, start, and verify both services.
./docker/deploy.sh

# Publish both via Tailscale Funnel (wires-host on :10000, wires-mcp on :443).
./docker/funnel.sh up all
```

Subsequent rollouts: `git push origin main && ssh <host> ./docker/deploy.sh`.
The named volumes `wires-host-data` and `wires-mcp-data` carry iroh
secrets, fabric state, the gateway JWT signing key, and per-user agent
data through container recreates, so the host's `EndpointId` and the
gateway's JWT issuer survive rollouts.

## User walkthrough (from the user's perspective)

1. Add the MCP server URL `https://mcp.example.com` to your MCP client.
2. The client opens the gateway's `/oauth/authorize` page in a browser.
3. A single QR code appears. The user scans it with the Wires iOS app;
   the gateway dispatches automatically into either the first-time
   pair flow (unknown root) or the returning-user biometric sign-in
   flow (known root).
4. The browser redirects back; the MCP client now has an access token
   bound to the user's fabric root pubkey.
5. The client can call MCP tools against the user's agent's caps:
   - **Substrate:** `wires_list_topics`, `wires_publish`, `wires_tail`.
   - **Channels:** `wires_list_channels`, `wires_create_channel`,
     `wires_channel_members`, `wires_invite_to_channel`,
     `wires_dm_open`, `wires_set_member_meta`.

## Known limitations (v1)

- `keys rotate` archives the old key but doesn't keep it in JWKS for
  an overlap window — existing access tokens become unverifiable on
  the next process restart. Wait out access-token TTL before
  restarting after a rotation.
- A user's topic set is fixed at pair time. To grant a paired gateway
  agent access to a new topic, `__cap.revoke` the existing cap and
  re-pair (the substrate's gossip-borne `__cap.grant` distribution is
  not yet implemented).
- Per-MCP-client distinction lives in logs only, not on the wires bus.
- The end-to-end acceptance test (`tests/end_to_end.rs`, marked
  `#[ignore]`) is a structural scaffold; filling in the test body
  requires factoring the pair-approve helper out of `wires-cli` and
  is tracked separately.
- DMs are operator-initiated only. `PairGrant` doesn't yet carry the
  operator's x25519 pubkey, so a paired agent's `dm_roster.json`
  knows every requester it has approved but doesn't know the
  operator. The operator can `wires dm open <agent>` outbound; the
  reverse direction needs a PairGrant extension.
