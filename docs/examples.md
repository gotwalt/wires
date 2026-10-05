# Example services

*The CLIs that teams reach today through vendor MCP servers, served as
wires services. Each directory under
[examples/services/](../examples/services/) is a `host.json` entry, a POSIX
`sh` wrapper, and a README with the vendor setup as commands, the admin's
`wires` edits, three calls an agent would make, and the vendor docs it
relies on.*

| Service | CLI | Pattern | The vendor's own mechanism |
|---|---|---|---|
| [aws](../examples/services/aws/) | `aws` | A, federated | IAM OIDC trust + `AssumeRoleWithWebIdentity`, from `AWS_WEB_IDENTITY_TOKEN_FILE` |
| [gcp](../examples/services/gcp/) | `gcloud` | A, federated | Workload Identity Federation, service account impersonation |
| [k8s](../examples/services/k8s/) | `kubectl` | A, federated | The API server trusts the IdP; the ID token is the bearer token |
| [github](../examples/services/github/) | `gh` | B, host-held | Fine-grained token in `GH_TOKEN` |
| [cloudflare](../examples/services/cloudflare/) | `wrangler` | B, host-held | Scoped API token in `CLOUDFLARE_API_TOKEN` |
| [vercel](../examples/services/vercel/) | `vercel` | B, host-held | Team token in `VERCEL_TOKEN` |
| [supabase](../examples/services/supabase/) | `supabase` | B, host-held | Access token in `SUPABASE_ACCESS_TOKEN` |
| [stripe](../examples/services/stripe/) | `stripe` | B, host-held | Restricted key in `STRIPE_API_KEY` |

## What changes for a team that already runs these CLIs

Anyone can run `gh` on their laptop. What wires changes is for the
organization: no per-person vendor credential to hand out or rotate (the
IdP sign-in is the person's credential; the host holds the rest), one
signed policy of who may use which service (`wires services` lists a
person's), removal by one `wires remove`, and output filtered before it
reaches the model, by the CLI's own flags (`--query`, `--format`, `--json
… --jq`) or by `wires call --jq/--head/--max-bytes`.

## Installing one

On the host: copy [examples/services/](../examples/services/) to
`/opt/wires-examples/services/` (each wrapper sources `common.sh` beside
its directory), write the role map the README shows, merge the example's
`host.json` `services` entry into the host's own, put the vendor's CLI on
`serve`'s `PATH`, and restart `wires serve`. The admin then runs one `wires
service add`.

Every wrapper reads `ROLE_MAP` from its `host.json` `env`: a file of
`<wires role> <value>` lines. `WIRES_ROLE`, the role that admitted the
caller, picks the line; a role with no line is refused. `ALLOW_COMMANDS`
overrides the subcommands the wrapper allows (`word`, or `word:sub` for a
pair); each wrapper's default leaves out the ones that print a credential
or run other commands. A wrapper's refusal exits 77, which `wires call`
reports as 1 with a note. Each wrapper then `exec`s the CLI, so the CLI is
the process the host stops if the caller goes away.

## Pattern A: the caller's ID token becomes their cloud identity

The host holds no cloud credential. `wires serve` hands every call the
caller's verified ID token (`WIRES_ID_TOKEN`); the wrapper writes it to a
file private to the call (under `STATE_DIR`) and points the cloud's own
exchange at it: `AWS_WEB_IDENTITY_TOKEN_FILE`, an `external_account`
credential file's `credential_source.file`, a kubeconfig's `tokenFile`. The
wires role picks the IAM role, the service account or the namespace, and
AWS names the session after the email, so CloudTrail shows the person.

## Pattern B: one scoped credential per role, on the host

The vendor takes no sign-in from your IdP, so the host holds one
credential per wires role, as narrow as the vendor allows. `host.json`'s
`env` is a literal, so it names the credential's file rather than holding
the credential: the role map points at a `0600` file only `serve`'s user
can read, and the wrapper reads it into the vendor's variable. The agent's
machine never receives it, the policy decides who may call, and the host's
log line names the person.

## Limits

**Both patterns.**

- The allowlist checks the first one or two words of the command, not what
  an allowed command does: the credential's scope is the boundary.
- The CLI runs as `serve`'s Unix user, and other processes of that user can
  read its environment, a pattern B credential included: [run services as
  a separate Unix user](deployment.md#run-services-as-a-separate-unix-user).
- `make demo-examples` tests the wrappers against stub CLIs. No example has
  been run against a live account.

**Pattern A.**

- It needs a real IdP: the cloud fetches the issuer's discovery document
  and keys from the internet, which `dev-mock-idp` on loopback can't serve.
- The cloud credentials exist inside one call, and the exchange fails once
  the sign-in expires (about an hour with Google), until `wires login`.
- **The cloud trusts the IdP, not wires.** Anyone holding the person's ID
  token for the wires OAuth client can make the same exchange directly, and
  `wires login` keeps one on the person's machine. `wires remove` stops the
  person's calls through wires; their cloud access ends at the IdP, or by
  narrowing the cloud's trust condition (an email pattern, a per-person
  binding). Keep endpoints like a cluster's API server reachable from the
  host's network only.
- A call through `wires gateway` carries a token minted for the gateway's
  OAuth client: the cloud must trust that audience too.
- AWS sees the `email` claim when the role is assumed, not afterwards;
  Google Cloud names the principal by `google.subject`. Per-person
  permissions beyond the trust condition come from the role map.

**Pattern B.**

- One credential per role, not per person: the vendor's own audit log
  shows the credential's owner, and the host's log line is where the person
  is.

## The hermetic test

`make demo-examples` (`.scripts/demo-example-services.sh`) serves all
eight through their real wrappers on one loopback host, with stand-in CLIs
that record what they were handed. It checks that pattern A wrappers pass
the caller's own token as a file and pick the cloud role by wires role,
that pattern B wrappers read the role's credential from its file, that an
unallowed subcommand (`gh auth token`) and an unmapped role are refused
with the CLI never run, that no vendor credential appears on the callers'
side, and that a removed person's call exits 77 with no CLI run.
