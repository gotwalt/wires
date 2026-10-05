# Example services

*The CLIs that teams reach today through vendor MCP servers, served as
wires services. Each directory under
[examples/services/](../examples/services/) is a `host.json`, a POSIX `sh`
wrapper, a role map, a `compose.yml` that runs them as a container, and a
README with the vendor setup as commands, the admin's `wires` edits, three
calls an agent would make, and the vendor docs it relies on.*

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

Each example runs as its own container, with no `sudo` anywhere: an image
holding `wires`, the wrapper and the vendor's CLI, installed the way the
vendor documents it ([examples/services/Dockerfile](../examples/services/Dockerfile),
one target per example), running as the unprivileged user `wires` (uid
10001), with `wires serve` as the container's process. Each directory's
`compose.yml`, modelled on `deploy/gateway/`, keeps the keystore in a named
volume at `/data` (`WIRES_HOME`), mounts `host.json` and the role map
read-only, and publishes no port, since wires dials out. From the
example's directory:

```bash
(cd ../../.. && make image)        # once per host: the wires image the examples copy wires from
docker compose build
docker compose run --rm <name> join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm <name> serve --check /etc/wires-examples/host.json
docker compose up -d
```

The admin then runs one `wires service add`. Each README has the steps in
between: the role map, the account-specific values in `host.json`, and for
pattern B, the credential file.

Without containers, the wrappers run from anywhere: point `host.json`'s
command and the role map at your copy of
[examples/services/](../examples/services/) (each wrapper sources
`common.sh` beside its directory), put the vendor's CLI on `serve`'s
`PATH`, and run `serve` as a user of its own (`make demo-examples` runs
them that way).

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
the credential: the role map points at a Compose secret
(`/run/secrets/<role>`), and the wrapper reads it into the vendor's
variable. The agent's machine never receives it, the policy decides who
may call, and the host's log line names the person.

On the host, the operator writes each credential into a `0700` directory
beside `compose.yml` (`secrets/`, ignored by git). Outside Swarm, Compose
ignores a secret's `uid` and `mode` and Docker mounts the file as it is,
so the file keeps the default `0644` that lets the container's user read
it, and the directory is what keeps the host's other users out: no `chown`,
no `sudo`.

## Limits

**Both patterns.**

- The allowlist checks the first one or two words of the command, not what
  an allowed command does: the credential's scope is the boundary.
- **The container is the separate Unix user** of
  [deployment.md](deployment.md#run-services-as-a-separate-unix-user):
  the CLI can't see the host's files, processes or other users, nor another
  example's container, its secrets or its callers' tokens. Its root
  filesystem is read-only, it holds no Linux capabilities, and
  `no-new-privileges` stops it gaining any.
- **Inside one container there is one user.** The CLI runs as `serve`'s
  user, so a call can read whatever `serve` can: the keystore at `/data`
  (the host's node key), every role's credential under `/run/secrets`, and
  other calls' environments, their callers' ID tokens included. An
  allowed command that reads local files (`gh api --input`, `aws s3 cp`)
  could send them out. Run roles that mustn't share a credential as
  separate containers, each with only its own secret.
- Running Docker is the one step that needs root on the host: the `docker`
  group is root in all but name, so use rootless Docker (or Podman) where
  that matters.
- `make demo-examples` tests the wrappers against stub CLIs, and `make
  demo-examples-docker` two images with stub CLIs. Every image builds with
  its real CLI, but no example has been run against a live account.

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

`make demo-examples-docker` (`.scripts/demo-example-services-docker.sh`,
opt-in, needs Docker) validates all eight `compose.yml` files, then builds
`github` and `aws` through theirs with a stub in place of the CLI. In each
it checks that `serve --check` accepts the mounted `host.json`, that the
process runs as uid 10001 on a read-only root, that the keystore volume
keeps the node id between runs, and that the wrapper, run as a call,
refuses an unallowed subcommand. For `github` it checks that the token
arrives from the Compose secret; for `aws`, that the call's token file
lands in the tmpfs. It removes every container, volume and image it made.
