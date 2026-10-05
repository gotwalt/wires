# 50 — Example services: the CLIs teams already reach through MCP

**Depends on:** 49, 45 and the docs pass after them (main stable) · **Status:** review (un-deferred by the human, 2026-10-05: "redo the demo, then the examples") · **Files:** `examples/services/<name>/` (new), `docs/examples.md` (new), `.scripts/demo-example-services.sh` (new), `.scripts/fixtures/stub-cli.sh` (new), `Makefile` (`demo-examples`), README's pointer to them

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

**Worker, 2026-10-05.** Branch `worker/50-example-services`. No Rust
changed. `make demo-examples`, `.scripts/demo-remote-cli.sh --quiet`,
`.scripts/demo-push.sh --quiet`, `cargo clippy -D warnings`, `cargo fmt
--check`, `cargo test --workspace`, shellcheck and `shfmt -d` over every
tracked shell file: all green.

**Questions settled (as directed).**
- Location: top-level `examples/services/<name>/`, plus a shared
  `examples/services/common.sh` the wrappers source (role map, allowlist,
  token file, session name, scrub), so the eight wrappers stay 15–40 lines.
- Secrets for pattern B: no code change. `host.json`'s `env` names a role
  map (`ROLE_MAP`), whose lines point at `0600` credential files only
  `serve`'s user reads; the wrapper reads the file into the vendor's
  variable. **Possible future `host.json` feature (not built):** an
  `env_files` map (`{"GH_TOKEN": "/etc/…/token"}`) read by `serve` at each
  spawn, which would make the wrappers for pattern B one line shorter and
  let a plain command (no wrapper) hold a secret. It wouldn't remove the
  need for the role map, so it's a small win.
- Accounts: none used. Pattern A and B are both tested hermetically
  against stub CLIs (`.scripts/fixtures/stub-cli.sh`); pattern A's token
  exchange is where the stubs stop, so the READMEs are runbooks for a real
  IdP and account. No example has run against a live account.

**The final list (8) and why.** Pattern A: `aws`, `gcp` (gcloud), `k8s`
(kubectl) — the three clouds/platforms with documented inbound OIDC
federation that a CLI consumes from a file. Pattern B: `github` (gh),
`cloudflare` (wrangler), `vercel`, `supabase`, `stripe`. Popularity check
(mcpmanager.ai "50 most popular MCP servers 2026", by search volume):
GitHub #3, Supabase #6, Linear #15, Stripe #26, Sentry #30, Vercel #39,
Cloudflare #44. Left out: **Linear** (no first-party CLI), **Sentry**
(`sentry-cli` is about releases and source maps, not the issues its MCP
server serves), **Azure** (`az login --federated-token` is a login step
that writes state; would be a ninth, kept to eight). Playwright, Figma,
Atlassian, Context7 top the list but aren't CLI-shaped admin tools.

**Verified mechanism per vendor** (URLs also in each README's Sources):
- AWS: `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` +
  `AWS_ROLE_SESSION_NAME` — https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html;
  session name 2–64 of `[\w+=,.@-]`, in CloudTrail; creds 1 h default —
  https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html;
  Google is built in (`Federated: accounts.google.com`,
  `accounts.google.com:aud`) — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html;
  condition keys — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif.
  **Correction to this card:** IAM *does* offer `email` as a condition key
  for OIDC (e.g. `accounts.google.com:email`), usable in the trust policy
  but "not available in session". The README says that.
- GCP: pool / `create-oidc` / `workloadIdentityUser` / `create-cred-config` /
  `gcloud auth login --cred-file` — https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers;
  `external_account` JSON (`credential_source.file`, `format.type: text`,
  `subject_token_type …:jwt`) — https://google.aip.dev/auth/4117;
  `google.subject` ≤127 chars, in Cloud Logging — https://docs.cloud.google.com/iam/docs/workload-identity-federation;
  `CLOUDSDK_CONFIG`, `CLOUDSDK_CORE_PROJECT` — https://cloud.google.com/sdk/gcloud/reference/config.
  The wrapper writes the credential file itself (per call) rather than
  using `create-cred-config`, since the token file path is per call.
- k8s: `--token`, `AuthenticationConfiguration` (`apiserver.config.k8s.io/v1`,
  `issuer.audiences`, `claimMappings.username.claim: email` implies the
  `email_verified` check) — https://kubernetes.io/docs/reference/access-authn-authz/authentication/;
  kubeconfig `tokenFile` (keeps the token out of argv) — https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/.
  Role → default namespace only; RBAC on the email decides.
- GitHub: `GH_TOKEN` (github.com / ghe.com only), `GH_PROMPT_DISABLED`,
  `NO_COLOR` — https://cli.github.com/manual/gh_help_environment;
  fine-grained PATs, org approval, Apps for org automation — https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens.
- Cloudflare: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`,
  `WRANGLER_SEND_METRICS` — https://developers.cloudflare.com/workers/wrangler/system-environment-variables/;
  `d1 list|execute --json` — https://developers.cloudflare.com/workers/wrangler/commands/d1/;
  `deployments list --name --json` — https://developers.cloudflare.com/workers/wrangler/commands/workers/;
  scoped tokens — https://developers.cloudflare.com/fundamentals/api/get-started/create-token/.
- Vercel: `VERCEL_TOKEN` (recommended over `--token`), `--scope`, `--team`,
  `VERCEL_ORG_ID` — https://vercel.com/docs/cli/global-options;
  `list --status/--environment/-m` — https://vercel.com/docs/cli/list;
  `vercel api --raw` (beta) — https://vercel.com/docs/cli/api.
- Supabase: `SUPABASE_ACCESS_TOKEN`, `projects list`, `functions list
  --project-ref` — https://supabase.com/docs/reference/cli/introduction;
  global `-o json` — https://supabase.com/docs/reference/cli/supabase-projects-list.
- Stripe: `STRIPE_API_KEY`, `STRIPE_DEVICE_NAME` ("visible in the
  Dashboard") — https://docs.stripe.com/cli/api_keys; resource commands —
  https://docs.stripe.com/cli/resources.

**Unverified (said so in the READMEs):** Google (`accounts.google.com`) as
a Workload Identity Federation issuer (found no statement either way);
that every Stripe resource command accepts a restricted key; per-project or
read-only scoping of a Supabase access token (found none, so the wrapper
allows `projects:list functions:list` only); `supabase db query` and
`branches list` (listed in the nav, undocumented, left out); `wrangler
whoami` flags (left out of the allowlist); managed clusters' (GKE/EKS/AKS)
OIDC setup (out of scope).

**Decisions in the wrappers.**
- Each wrapper `exec`s the CLI (the host SIGKILLs only its direct child on
  disconnect, `wires/host/service.rs`), so nothing is left to delete a
  pattern A token file: each call puts its token in `STATE_DIR/call.XXXXXX/`
  (0700, umask 077) and first sweeps call dirs over 60 minutes old, whose
  tokens have expired. The token in the file is the same one already in the
  child's environment, so it adds no exposure to `serve`'s user.
- `HOME` for pattern A is the call's own directory (no AWS/gcloud cache
  shared between people); `AWS_EC2_METADATA_DISABLED=true` so an instance
  role is never the fallback.
- `scrub` unsets `WIRES_ID_TOKEN`, `WIRES_PUSH_TOKEN`, `WIRES_PUSH_SOCKET`
  before exec (the stub asserts no `WIRES_ID_TOKEN` reaches a CLI).
- **A subcommand allowlist** (`ALLOW_COMMANDS`, `word` or `word:sub`) was
  needed, beyond the brief: `gh auth token`, `aws configure
  export-credentials` and `gcloud auth print-access-token` would hand the
  agent the very credential the example keeps on the host. Defaults leave
  those out; the demo asserts `gh auth token` is refused with gh never run.
- Refusals exit 77; `wires call` reports a remote 77 as 1 with the note
  "exit 77 means the host refused the call", which is slightly off for a
  wrapper's refusal. Not changed (Rust); the docs say what the caller sees.
- `STRIPE_DEVICE_NAME=wires:<email>` is the one pattern B vendor knob that
  names the person; others don't have one.

**A finding the integrator should weigh (pattern A).** The cloud trusts the
IdP, not wires: anyone holding the person's ID token for the wires OAuth
client can make the same exchange directly, and `wires login` keeps one in
the person's keystore (`idp-token.jwt`). So for pattern A, "no credential
on the agent's machine" and "removal by one `wires remove`" hold only for
access through wires; the cloud access ends at the IdP or by narrowing the
cloud's trust condition. `docs/examples.md` § Limits states this once.
Pattern B has no such gap. A gateway call's token has the gateway's
audience, so a pattern A trust must list it too (stated).

**Skipped:** step 5 of the brief (a token side-by-side against a vendor MCP
server): every candidate vendor MCP server needs a live, authenticated
account, so it can't be run honestly without one.

**Outside the lane:** `docs/board/README.md` (card 50's row → review). Not
edited, for the docs pass: `CLAUDE.md` (Build System's command list and the
`.scripts/` / layout paragraphs could name `make demo-examples`,
`.scripts/demo-example-services.sh`, `.scripts/fixtures/stub-cli.sh` and
top-level `examples/services/`), `docs/testing.md` (the demo list).

**Containers, 2026-10-05.** Branch `worker/50b-examples-in-containers`. The
human: "update the examples/ to not use sudo unless absolutely necessary
… operate as dockerized services". No `sudo` is left in `examples/`,
`docs/examples.md` or the scripts; no Rust changed.
- **Shape.** One `examples/services/Dockerfile`: a `base` stage
  (`debian:bookworm-slim`, the repo image's Debian, user `wires` uid 10001,
  `/data` owned by it, `common.sh`, `wires` copied from `WIRES_IMAGE`,
  default `wires:dev` from `make image`, so wires isn't rebuilt), a
  `base-node` stage (node and npm copied from `node:24-bookworm-slim`), one
  target per example installing the vendor's CLI the vendor's documented
  way (cited at each stage), and a `stub` target for the test. Each
  example's `compose.yml` (modelled on `deploy/gateway/`): `wires serve
  /etc/wires-examples/host.json` as the process, `init`, `read_only`,
  `cap_drop: ALL`, `no-new-privileges`, the keystore as a named volume at
  `/data`, `host.json`, the role map (now a committed `<name>.roles`) and
  the k8s CA as Compose `configs:`, `STATE_DIR` / `HOME` as tmpfs owned by
  10001, no ports. `host.json` and the wrappers are unchanged, so the
  hermetic demo is too.
- **Secrets.** Pattern B credentials are Compose `secrets:` at
  `/run/secrets/<role>`. Docker Compose 5.1 ignores a file secret's
  `uid`/`mode` outside Swarm (it warns), so the file keeps its host mode:
  the READMEs have the operator write it `0644` inside a `0700` `secrets/`
  directory (git-ignored). A `0600` file is unreadable to uid 10001.
- **The one root left:** running Docker itself (the `docker` group is
  root-equivalent; rootless Docker or Podman avoids it). Said once in
  `docs/examples.md` § Limits, with what the container isolates (host
  files, processes, other examples) and what it doesn't (one user inside:
  a call can read the keystore, every role's secret in that container, and
  other calls' environments; separate containers per role if that
  matters).
- **Tests.** `make demo-examples` unchanged. New opt-in `make
  demo-examples-docker` (`.scripts/demo-example-services-docker.sh`, ~10 s
  warm): validates all eight compose files; builds `github` and `aws`
  with the stub CLI via their own compose files plus an override; checks
  `serve --check`, uid 10001 on a read-only root, the node id surviving in
  the volume, the wrapper as a call (secret read for github, tmpfs token
  file for aws, a refused subcommand at 77); removes everything
  `wires-example-test-*` it made. Every real target was also built once
  and its CLI run as uid 10001 (aws-cli 2.37.9, gcloud 587.0.0, kubectl
  v1.37.1, gh 2.102.0, wrangler 4.147.0, vercel 62.4.0, supabase 2.119.0,
  stripe 1.53.0); wrangler, vercel and gcloud also ran on a read-only root
  with a tmpfs HOME. No live account.
- Hadolint clean (DL3008/DL3016 ignored globally: apt/npm left unpinned so
  a rebuild takes the vendor's current release; DL3022 at the stub's named
  build context).
