# 50 — Example services: the CLIs teams already reach through MCP

**Depends on:** 49, 45 and the docs pass after them (main stable) · **Status:** backlog; **deferred** (the human, 2026-10-05: "write the card but defer it until we're more stable on main") · **Files:** `examples/services/<name>/` (new), `docs/examples.md` (new), `.scripts/demo-example-services.sh` (new), README's pointer to them

## Why

The human (2026-10-05): "build out a set of example services like this,
probably gcp, cloudflare, vercel, and other most-used mcps that also have
CLIs today. … showing that 'you can do what you're already doing, but more
easily in wires' is a goal we should have."

The people we pitch already run MCP servers for their cloud and SaaS tools.
Most of those vendors also ship a CLI. A worked example for each, copied
from a directory and running in minutes, shows the claim instead of arguing
it: the same tool, reached by service name, with the person's own identity,
and with no credential on the agent's machine.

Every example's README sentence must pass the rebuttal test
([storytelling.md](../../storytelling.md) §1). The honest rebuttal is "I can
already run `gh` on my laptop". The answer is what changes for the org:
no per-person credential to hand out or rotate, removal by one `wires
remove`, one signed policy of who may use what, and output filtered before
it reaches the model.

## Two patterns

**A. Federated: the caller's ID token becomes a per-person cloud identity.**
The host holds no cloud credential. A wrapper exchanges `WIRES_ID_TOKEN` (aud
= the wires client ID) for short-lived credentials, maps `WIRES_ROLE` to a
cloud role, and names the session after `WIRES_CALLER_EMAIL`, so the cloud's
own audit log shows the person.

| Service | CLI | Exchange (verify each before building) |
|---|---|---|
| `aws` | `aws` | IAM OIDC provider + `AssumeRoleWithWebIdentity`; the CLI does it from `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` + `AWS_ROLE_SESSION_NAME` (worked through in the 2026-10-05 session) |
| `gcp` | `gcloud` | Workload Identity Federation: an OIDC pool/provider, a credential config whose `credential_source.file` is the token file, optional service-account impersonation |
| `azure` | `az` | A federated credential on an app registration; `az login --service-principal --federated-token` |
| `k8s` | `kubectl` | An API server that trusts the issuer takes the ID token as a bearer token directly (`--token`), with RBAC on the email or groups claim |

Limits to state on each: STS-style exchanges fetch the issuer's discovery
document from the internet, so these need a real IdP, not `dev-mock-idp`;
credentials last no longer than the sign-in (about an hour with Google); IAM
conditions usually see `aud` and `sub`, not `email`, so per-person policy in
the cloud comes from the wires role → cloud role mapping.

**B. Host-held: one scoped credential on the host, wires decides who.**
For vendors with no inbound OIDC federation, the host holds one narrowly
scoped token in `host.json`'s `env` (or a file only `serve`'s user reads).
The agent's machine never sees it; the signed policy decides who may call;
the host's per-call log line says who did; removal is `wires remove`, not a
token rotation.

| Service | CLI | Notes |
|---|---|---|
| `cloudflare` | `wrangler` | API token scoped to the account/zones the example needs |
| `vercel` | `vercel` | Team token; `--token` or `VERCEL_TOKEN` |
| `github` | `gh` | A GitHub App installation token (short-lived) beats a PAT; `GH_TOKEN` |
| `sentry` | `sentry-cli` | Org auth token |
| `stripe` | `stripe` | Restricted key, test mode for the demo |
| `supabase` | `supabase` | Access token |

Choose the final list by what the MCP side ships most (check the most-used
remote MCP servers at the time this is picked up), not by this table.
Five to eight examples, at least two of pattern A.

## Do

1. Per example, under `examples/services/<name>/`: the `host.json`
   fragment, the wrapper (POSIX `sh`, shellchecked), the cloud/vendor setup
   the admin does once (as commands, not screenshots), the `wires role` /
   `wires service` edits, and three agent-shaped calls that use the CLI's
   own output filtering (`--query`, `--format`, `--json … --jq`).
2. `docs/examples.md`: one table of what is there and which pattern, the
   two patterns explained once, and each pattern's limits stated once.
3. Pattern B examples get a self-asserting script that runs hermetically
   with `dev-mock-idp` and a stub CLI on `PATH` that records its argv and
   env (proving the agent never sees the vendor token and that the wrapper
   passes the person through). Pattern A gets a runbook for a real IdP and
   a real account; it can't be hermetic.
4. A side-by-side for one or two of them against the vendor's MCP server:
   the same task, the tokens it cost (reuse `bench/`'s method), and what
   the agent had to hold.

## Questions to settle when it's picked up

- Do pattern B wrappers belong in `host.json` (`env` holding a secret) or
  should `host.json` gain a way to read a secret from a file? Today `env` is
  a literal.
- Is `examples/` (top level) right, next to `wires/examples/kv` (the native
  service)?
- Which accounts we demo against, and who pays for them.

## Notes
