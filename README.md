# wires

> **Run a CLI on another machine from your agent. The machine is reached by
> public key, never by network path; the caller is authenticated by your IdP;
> and every call lands on an encrypted channel that anyone you authorize can
> watch, without access to the caller or the machine running the CLI.**

```
          admin: wires init · invite · remove   (holds the root key: who's in)
                               │
                               │  re-key on every invite and remove
                               ▼
  ┌───────────────────────── channel "ops" ─────────────────────────┐
  │  encrypted to the roster's current members; no server owns it   │
  │  re-keys · host announcements (which tools, sealed per reader)  │
  │  IdP-signed identity claims · call records, written by the host │
  └─────────────────────────────────────────────────────────────────┘
        ▲ identity claim          ▲ announcements, ▶ ■ ✗ records   │
        │ (wires login)           │                                ▼
  caller (your agent)        host: wires serve host.json       observer
  join · login · call ──────▶ runs one allowlisted CLI       wires watch
                     QUIC,    (host.json: what runs,        (holds neither
                  dialed by   and which roles may run it)    end's keys)
                  host's key
```

**What you just saw**, in the order the demo runs it:

- Joining is one exchange with the admin: send `wires id`, get back an invite. After that, hosts, tools, identities and calls all arrive on the channel.
- The host runs `wires serve host.json`. It has no TCP listener and opens no firewall port, and unauthenticated peers are refused at the handshake. A caller reaches the CLIs `host.json` lists, not the machine.
- The caller signs in once (`wires login`), which binds your IdP's ID token to its node key. The host enforces `host.json`'s roles on every call. Every reader of the channel checks the IdP's signature itself.
- The agent runs `wires call db_query -- "…"` and filters output before it reaches context. `wires mcp` is only there for clients that can't run a CLI.
- The host writes a record of every call, refusal and exit onto the channel. The observer reads it without either end's credentials.
- `wires remove` re-keys the channel. The removed caller's next call exits 77, the refusal is on the channel, and nothing restarts.

## Where each guarantee lives

| Guarantee | Lives in | Checked by |
|---|---|---|
| **Reach** | The host's node key. Callers dial a key; the host binds UDP for QUIC and has no TCP listener. | The host, at the QUIC handshake: the caller's key must hold a root-signed membership and be in the current roster. |
| **Policy** | `host.json` on the host: which CLIs run, and which roles may run each one. Default deny. | The host, on every call. |
| **Identity** | Your IdP's ID token, bound to the caller's node key at `wires login` (the OIDC `nonce` is a hash of the key) and published on the channel. | The host, which enforces it, and every reader of the channel, each checking the IdP's signature independently. There's no wires identity service. |
| **Observability** | Call records written by the host that ran the command, signed by its key, on the channel. | Any member. An observer needs a membership and nothing from the caller or the host. |

## Walkthrough

Four machines (they can be four `WIRES_HOME` directories on one machine):
**admin**, **workbench** (the host), **laptop** (the caller: your agent), and
**observer**. Build with `cargo build --release -p wires` (or `docker build
.`), then put `target/release/wires` on each machine's `PATH`.

The output below is from a real run on the current binary. It used one
machine with four short `WIRES_HOME`s, and the stand-in IdP that
`.scripts/demo-remote-cli.sh` uses (`wires dev-mock-idp`, from a build with
`--features dev-mock-idp`) in place of
Google, so `login` there also passed `--issuer`/`--no-browser`. Log lines at
`INFO` are left out. `./.scripts/demo-remote-cli.sh` runs the same sequence
and asserts every step.

**1. admin: start the fabric.** This creates the root key and the admin's own
node, and names the channel.

```console
$ wires init --channel ops
fabric e010054b9652794b6c2ab66d3e43ac45c74ec400658291416e78ee063a40264c
node e8bb4ff61f7c0624ec51f0b7e300b2e35899dec29bc88903d79983d6740bd465
channel "ops" (roster version 1, 1 member: this node)
next: on each joining machine run `wires id`, then here `wires invite <node-id> --name <label>`
```

**2. Every other machine: send your id, join with the invite.** The host goes
first, because it will be everyone else's bootstrap peer.

```console
workbench$ wires id
wires id: generated this node's key (node.seed); send the id to your admin
001753930c41ce47740c4206b7a9983bcfeb24ae2489dbe3c19507ce7d8a2261

admin$ wires invite 001753930c41ce47740c4206b7a9983bcfeb24ae2489dbe3c19507ce7d8a2261 --name workbench
wires: invited 00175393… as "workbench" (roster version 2, 2 members)
wires: roster version 2: no other member to re-key
wires: no bootstrap peer is known yet, so the token carries none: the joiner can still serve (and be everyone else's bootstrap) — pass its ticket to the next `wires invite --peer <ticket>`
wires: on the joining machine: wires join eyJjaGFubmVsIjoib3BzIiwiZW50cnkiOnsia2V5…

workbench$ wires join eyJjaGFubmVsIjoib3BzIiwiZW50cnkiOnsia2V5…
joined fabric e010054b… as 00175393… on channel "ops" (roster version 2)
```

(`join` also printed a hint naming `serve --audit-topic`, a flag that no
longer exists; `wires serve host.json` is what prints the ticket.) The token
(about 2 KB) isn't a secret. Everything in it is public or sealed
to the invitee's key.

**3. workbench: say what runs and who may run it.** Everything the host
decides is in `host.json`. A command is an argv, exec'd directly and never
through a shell, with the caller's arguments appended. sqlite3's `-safe`
turns off its `.shell`/`.system` dot-commands.

```json
{
  "version": 1,
  "channel": "ops",
  "identity": { "issuers": [
    { "issuer": "https://accounts.google.com", "audiences": ["<client id>.apps.googleusercontent.com"] }
  ] },
  "roles": { "analyst": [ { "email": "*@example.com" } ] },
  "tools": {
    "db_query": {
      "description": "Read-only SQL against the orders database",
      "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"],
      "allow": ["analyst"]
    }
  }
}
```

```console
workbench$ wires serve --check host.json
host.json ok (version 1)
channel: ops
trusted issuers:
  https://accounts.google.com  audiences: <client id>.apps.googleusercontent.com
roles:
  analyst  email=*@example.com
  member  (built in) any roster member, no identity needed
tools:
  db_query  may run: analyst
    command: sqlite3 -safe -readonly -header -column orders.db
    Read-only SQL against the orders database

workbench$ wires serve host.json
wires watch: topic "ops" (84fa745e…) as 00175393…
wires watch: fabric e010054b…, roster version 2
share to bootstrap: eyJmYWJyaWMiOiJlMDEwMDU0Yjk2NTI3OTRi…
```

(The issuer line in the recorded run showed the stand-in IdP's URL.)

**4. admin: invite the laptop and the observer.** Give the first of these
invites the host's `share to bootstrap:` ticket once. The admin remembers it
for every later invite and re-key.

```console
admin$ wires invite a9ab1b64ad775a3670b4b4bfcc17ff14b57eb7c1d0b55628631d53959fcf41c7 --name laptop --peer eyJmYWJyaWMiOiJlMDEwMDU0Yjk2NTI3OTRi…
wires: invited a9ab1b64… as "laptop" (roster version 3, 3 members)
wires: roster version 3: re-key published on the channel (via 00175393…)
admin$ wires invite a5c4254f83ba0b135051d0db5fb19d5b270f61b8057d7f904040c3018ea056da --name observer
wires: invited a5c4254f… as "observer" (roster version 4, 4 members)
wires: roster version 4: re-key published on the channel (via 00175393…)

laptop$ wires join eyJ…
joined fabric e010054b… as a9ab1b64… on channel "ops" (roster version 3)
1 bootstrap peer(s) recorded; `wires watch` needs no --peer
```

The host was never restarted or reconfigured: each invite's re-key reached it
on the channel.

**5. observer: watch.** The observer verifies identity claims itself, so it
is told which OAuth client ids to accept (the issuer defaults to Google).

```console
observer$ WIRES_OIDC_AUDIENCE=<client id>.apps.googleusercontent.com wires watch
```

**6. laptop: sign in, find the tool, call it.** Nothing is configured on the
laptop. Before sign-in the host lists nothing to it:

```console
laptop$ wires tools
wires tools: 1 host on channel "ops" announces nothing you may use: 00175393

laptop$ wires login --topic ops --client-id <client id>.apps.googleusercontent.com --client-secret <secret>
wires login: node a9ab1b64… is alice@example.com (token stored in …/idp-token.jwt, valid until unix 1790144261)
wires login: identity claim published on topic "ops"

laptop$ wires tools
db_query  on 00175393  Read-only SQL against the orders database
# call: wires call <name> [--jq FILTER] [--head N] [--max-bytes N] -- <args>. Filter with the command's own flags (e.g. gh --json f --jq …) or --jq/--head/--max-bytes; there is no shell, so pipes are not available.

laptop$ wires call db_query -- "select count(*) from orders"
count(*)
--------
       7

laptop$ wires call db_query --head 4 -- "select customer, total from orders order by total desc"
customer  total
--------  ------
umbrella   999.0
globex    310.25
```

`--head` (like `--jq` and `--max-bytes`) is applied inside `wires call` on the
laptop. The host never sees it, and the tool's exit code passes through.

**7. admin: remove the laptop.**

```console
admin$ wires remove laptop
wires: roster version 5: re-key published on the channel (via 00175393…)
removed a9ab1b64… (laptop) (roster version 5, 3 members)

laptop$ wires call db_query -- "select count(*) from orders"
wires: denied by responder: roster inclusion rejected: not in the current roster (removed at version 5)
$ echo $?
77
```

**What the observer printed** through all of this (a test message the admin
published with `wires advanced publish` is left out; the issuer is the
stand-in IdP's):

```
05:17:39 00175393 📣 announces tools (none open; 0 sealed entries)
05:17:41 a9ab1b64 🪪 identity a9ab1b64 is alice@example.com (verified by http://127.0.0.1:61071)
05:17:41 00175393 📣 announces tools (none open; 1 sealed entry)
05:17:46 00175393 ▶ 72ea alice@example.com (a9ab…) [analyst] db_query "select count(*) from orders"
05:17:46 00175393 ■ 72ea exit 0 · 10 ms · 27 B out · blake3 8b4c…
05:17:47 00175393 ▶ 29db alice@example.com (a9ab…) [analyst] db_query "select customer, total from orders order by total desc"
05:17:47 00175393 ■ 29db exit 0 · 5 ms · 152 B out · blake3 734f…
05:17:51 e8bb4ff6 🔑 re-key to roster version 5 (3 members)
05:17:51 00175393 📣 announces tools (none open; 1 sealed entry)
05:17:55 00175393 ✗ a9ab… db_query denied: roster inclusion rejected: not in the current roster (removed at version 5)
```

The second column is the node that wrote the line. Call records come from the
host (`00175393`), and the identity claim comes from the caller. The observer
only sees the announcements' sealed entries as a count: it isn't in role
`analyst`, so none of them are addressed to it.

The scripted demo covers more than this walkthrough: a call refused before
sign-in, a signed-in non-analyst who sees no tools and is refused by name,
SQL sent on stdin, the same tool through `wires mcp`, and `.shell id` refused
by `sqlite3 -safe`:

```bash
./.scripts/demo-remote-cli.sh            # builds with cargo; narrated, ~1 min; --quiet for assertions only
```

## Why it's built this way

**The CLI first; MCP for backward compatibility only.** Models already know
CLIs, and a CLI lets the agent pick the fields it wants before anything
reaches context: `gh … --json tagName --jq …`, or `wires call`'s own
`--jq/--head/--max-bytes` for tools without a filter. That filtering, not
tool schemas, is where the measured difference comes from. Claude Code's
default tool search already keeps MCP schemas down to about 400 tokens. On
five read-only GitHub tasks (`bench/REPORT.md`):

| arm | median total input | Σ cost, 25 runs | accuracy | permission refusals |
|---|---|---|---|---|
| GitHub MCP server, Claude Code default (tool search on) | 21,088 | $1.87 | 25/25 | 0 |
| GitHub MCP server, tool search off | 30,630 | $1.40 | 25/25 | 0 |
| `wires call gh`, plus shell pipe helpers | 10,539 | $0.48 | 25/25 | 7 |
| bare `gh`, plus shell pipe helpers | 6,997 | $0.42 | 25/25 | 8 |
| `wires call gh` only, no shell (arm 5) | 10,713 | $0.39 | 25/25 | 0 |

Arm 5 shows the efficiency holds when `wires call` is the only thing the agent
is allowed to run. In that arm, most filtering used `gh`'s own `--jq` (20 of
39 calls), and 4 calls used `wires call --jq`. Caveats: n = 5 per cell,
one model (Opus 5.5), one MCP server (GitHub's, whose payloads are unusually
large), and stripped-down sessions with no CLAUDE.md, skills or memory, so
the percentages overstate what a full session would see. An MCP server with
field selection would close much of this gap. `wires mcp` serves the same
tools, with the same `jq`/`head`/`max_bytes` fields, to clients that can only
speak MCP. New agents should use the CLI.

**Dial by key, not by host and port.** Tailscale gives the caller's machine a
network path to the host. Its ACLs can narrow that to a port, and the service
on that port is then guarded by its own auth. Wires gives the caller a key-addressed path to one
allowlisted CLI. On the host there is no TCP listener and no firewall port
opened; iroh binds UDP for QUIC (direct, or through a relay), and
unauthenticated peers are refused at the handshake. In the two-machine run
(card 08), `ss` on the host showed zero TCP listeners and two UDP sockets.

**The host writes the log.** The record of a call is written by the process
that ran it, the one place the call can happen, and published on the channel
under the host's key. The caller can't write a record that carries that key,
and no gateway sits in the path to own it. Anyone who is a member can read it without the caller's or
the host's credentials.

**Identity is the IdP's own signature.** `wires login` puts the caller's key
hash in the OIDC `nonce`, so the ID token names the key it belongs to. The
host enforces `host.json`'s roles against it, and every reader verifies it
against the IdP's published keys. There's no wires-run attestor to trust, no
auth code in the CLI being exposed, and issuers are listed per host, so two
organizations' IdPs can share a channel.

**The channel is the directory.** Hosts announce their tools on the channel,
and each tool's listing is sealed to exactly the members whose verified
identity the host's policy lets run it. `wires tools` shows what *you* can
run. Other members learn that the host announced and how many sealed
entries it carries, but not the gated tools' names (card 15 lists exactly what
leaks). This is privacy, not access control: the host still decides every
call, and naming a tool you can't see gets a refusal with the reason. A
cold `wires call` catches up from the channel in at most 2 s and caches what
it finds in `directory.json`.

**Policy in one file.** `host.json` holds the tools, the trusted issuers and
the roles, with default deny and unknown keys rejected. The role table is one
implementation of a `Policy` trait (`wires/host/policy.rs`) that receives the
whole call: every claim the IdP signed, the caller's node, the roster version,
the tool and its arguments. Rules a table can't express (CEL, Rego, a webhook)
would be a second implementation behind a `"policy"` block. That block
doesn't exist yet.

**Hosts can call the agent back.** A webhook needs the receiver to have a
public HTTPS endpoint, and an agent on a laptop or in a sandbox has none. A
caller here is addressed by its key, so a host can push to it with neither
side exposing anything: `wires push --to "$WIRES_CALLER_NODE" --subject
build-41 -- "failed: …"` from a tool's background job (every tool gets its
verified caller's id in that variable). The host queues the message, dials the
caller's resident `wires watch` by key, and otherwise keeps it (24 h by
default) for the caller's next `wires inbox`, which fetches it. No harness
change is needed: an agent runs `wires inbox` on a loop, or `wires inbox
--wait` as a background command, which costs no turns while it waits.
`host.json`'s `push.allow` decides who may receive (default nobody), checked
at send and again at delivery or fetch, so a removed member gets nothing. Each
push is recorded on the channel (`⇢ … "build-41" fetched`), subject only
unless `"log_body": true`. Every inbox line starts with the sender as the
caller verified it, because a push is **untrusted input to a model**:

```
2026-09-23 16:04:05Z  from host 51442ef9 (verified)  build-41  failed: test_orders_total
```

## Giving an agent only `wires`

A Claude Code rule like `Bash(wires call:*)` is **not airtight** on its own.
Claude Code does check each part of a compound command, and none of the
chained, substituted or redirected commands the probe tried got past it. But
it also auto-allows read-only commands such as `cat` and `echo` inside the
working directory, and `< file` or a glob can send working-directory files to
the host as input. The agent can also pass `wires call`'s own override flags
(`--tools-file`, `--*-file`, `--relay-url`). Evidence and method:
[docs/agent-sandbox.md](docs/agent-sandbox.md).

To make `wires` the boundary, use a structural setup:

- a container or sandbox whose `PATH` holds only `wires`, in an empty
  working directory with no secrets in the environment, with
  `WIRES_LOCKED=1` set (or `"locked": true` in a `tools.json` the agent
  can't write). Locked, `wires call` and `wires mcp` refuse every flag
  that would point them at other credentials, another tools map or
  another relay (`--tools-file`, `--*-seed*`, `--membership*`,
  `--inclusion-proof*`, `--relay-url`); only `--jq`, `--head`,
  `--max-bytes`, the tool name and its arguments are accepted. `wires call`
  also refuses data on stdin, so `< file` can't ship a local file to the
  host; pass input as arguments, or set `WIRES_LOCKED_STDIN=allow` if your
  tools need piped input. (`wires mcp`'s `stdin` field is unaffected: it
  is the model's own text.)
- or `wires mcp` as the agent's only tool, with no Bash tool at all.

## Known trade-offs

- **A removed member learns who's left.** The re-key record that removes a
  member is published under the outgoing key, so the removed member can read
  the surviving members' ids (never the new channel key). This weakens the
  committed roster's "the head hides the member set" property for removed
  members.
- **Memberships don't renew yet.** Memberships and roster heads expire after
  `--ttl` (default 30 days), and nothing renews them automatically. For now,
  re-issue them with `wires invite <id>`.
- **A member only reads the channel from when it joined.** Messages under
  keys from before its invite are stored but not shown.
- **The IdP must be trusted per reader.** A host trusts the issuers in
  `host.json`, and an observer trusts `WIRES_OIDC_ISSUER`/`WIRES_OIDC_AUDIENCE`.
  Nothing on the channel tells a reader which IdP to believe.

## Not yet

- **Joining by domain** (`wires join acmecorp.com`, a published root key, a
  front desk that admits by IdP rule). This is an open question and not
  designed ([card 18](docs/board/backlog/18-front-door-OPEN.md)). Today the
  invite introduces the root key (trust on first use).
- **The recorded two-machine demo** with real Google sign-in and Claude Code
  as the agent ([card 08](docs/board/doing/08-demo-two-machine.md);
  script in [docs/demo.md](docs/demo.md)).
- Membership renewal; host display names in `wires tools`; `wires mcp`
  noticing new announcements without a restart; a key-less witness that
  stores call records without decrypting them ([card 09](docs/board/backlog/09-witness.md)).

## Why not…

| | |
|---|---|
| **…Tailscale?** | Tailscale exposes the service to the caller's machine: a network path to the host, narrowed by ACLs to a port at best. Wires gives a key-addressed path to one allowlisted CLI: no TCP listener, no firewall port opened, and unauthenticated peers are refused at the handshake. |
| **…an MCP gateway's logs?** | A gateway's log belongs to whoever runs the gateway, and covers only traffic routed through it. Here the record is written by the host that ran the command and published on a channel that members read without either end's credentials. |
| **…OAuth on each MCP server?** | Each server then integrates your IdP, and its log is the only evidence of who called. Here the CLI has no auth code: the host checks the IdP-signed token bound to the caller's key, and every reader can verify the same token. |
| **…a leaner MCP server?** | It would close much of the token gap, since the gap comes from output size. The CLI gets it without rewriting anything, and the case for wires rests on reach, identity and the host-written record, not on tokens. |

# Reference

## Commands by role

`wires --help` lists only these:

| Role | Command | What it does |
|---|---|---|
| **admin** | `wires init [--channel ops] [--ttl 30d]` | Create the root key and this node, commit roster version 1, record the channel. |
| | `wires invite <node-id> [--name l] [--ttl 30d] [--peer <ticket>]` | Add a node and print its join token (stdout). The commit's re-key is published on the channel. |
| | `wires remove <name\|node-id>` | Drop a node; the re-key is published on the channel, and hosts that adopt it refuse the node's next call. |
| | `wires advanced …` | Plumbing (below). |
| **host** | `wires serve host.json` | Expose the file's tools, check every caller's membership, roster inclusion and role, exec the tool per call, announce the tools, and record every call and refusal on the file's `channel`. `--check` validates and prints who may run what. |
| | `wires push --to <node-id\|role> --subject S [--ttl D] -- <body>` | Hand a message for a caller to this machine's running `serve` (body from stdin if none is given). Prints `delivered`, `queued` or `denied` per recipient; exits `77` if every recipient was refused. |
| **caller** | `wires id` | Print this node's id (creating its key on first use). |
| | `wires join <token>` | Install an invite: credentials, the channel, bootstrap peers. |
| | `wires login --topic ops` | Sign in with your IdP (Google by default; `--issuer`, `--client-id`, `--client-secret` or `WIRES_OIDC_*`) and publish the key-bound claim. |
| | `wires call <tool> [--jq F] [--head N] [--max-bytes N] -- <args>` | Run a remote CLI by name. Stdio passes through and its exit code becomes `call`'s. A refusal exits `77`. `host8/tool` picks one host when several serve a name. |
| | `wires tools` | List the tools the channel's hosts let you run. `add`/`list`/`rm` edit local aliases in `tools.json`. |
| | `wires mcp` | Serve the same tools as MCP tools over stdio, for clients that can't run a CLI. |
| | `wires inbox [--wait [--timeout D]] [--json]` | Print what hosts pushed to you, sender first, and mark it read. Without a running `watch` it first fetches from the channel's hosts. `--wait` blocks until something arrives; `--timeout` exits `124`; a refusal by every host exits `77`. Obeys locked mode like `call`. |
| **observer** | `wires watch [channel]` | Stream the channel: calls, refusals, identities, announcements, pushes and re-keys. Also prints this node's bootstrap ticket, and receives this member's pushes into its inbox. |

For an MCP-only client, the whole config is:

```json
{ "mcpServers": { "wires": { "command": "wires", "args": ["mcp"] } } }
```

`wires advanced` holds the plumbing the role commands are built from:

| Command | What it does |
|---|---|
| `advanced member` | Root-sign a membership for a node. |
| `advanced roster` | `add`/`remove` members, `commit` a signed head with per-member proofs and sealed channel keys, `head` to print it. |
| `advanced import` | Install a membership, inclusion proof, roster head or sealed channel key by hand. |
| `advanced publish <channel> -m <text>` | Put a message on the channel, through a running `watch` or as a one-shot node. |

## host.json

| Key | Meaning |
|---|---|
| `version` | Required, `1`. Unknown keys anywhere are an **error**, so an older host never silently misreads a newer file. |
| `channel` | Where calls, refusals and announcements are recorded, and where callers' `wires login` claims are read. It can be left out only when every tool allows nothing but `member` (then there's no audit and no identity). |
| `identity.issuers` | The IdPs whose ID tokens the host verifies, each with the OAuth client ids (`audiences`) it accepts **from that issuer**. |
| `roles` | Name → a list of matchers, any of which may match (OR). A matcher's keys must all match (AND): `issuer` (exact), `email` (exact or `*@domain`), `org` (Google's `hd`), `group`. |
| `tools` | Name → `command` (argv, no shell), optional `description`, and `allow`: the roles that may run it. |
| `push` | Optional. `allow`: the roles whose members may receive `wires push` from this host (none by default). `log_body`: also record each push's body on the channel (default `false`: subject only). Needs a `channel`. |

Nothing is allowed by default; a tool with an empty `allow` refuses every
call. The built-in role `member` admits any roster member with no IdP
requirement, and applies only where a tool's `allow` lists it. A refusal names
the rule that failed:

```
✗ b7cd… db_query denied: no identity claim for b7cdcba5; run `wires login --topic ops`; db_query needs a verified identity in role analyst (email=*@example.com)
```

and a signed-in caller in no role gets, on stderr:

```
wires: denied by responder: identity bob@other.org (from http://127.0.0.1:60885) is in no role allowed to run db_query: analyst (email=*@example.com)
```

A host that admits a call passes the verified caller to the tool as
environment: `WIRES_CALLER_NODE`, `WIRES_FABRIC_ROOT`,
`WIRES_MEMBERSHIP_NOT_AFTER`, `WIRES_ROSTER_VERSION` and `WIRES_TOOL`. These
are derived by the host, never taken from the caller, and any inherited
`WIRES_*` is scrubbed first.

## The keystore

Each node's state is a directory: `$WIRES_HOME`, else
`$XDG_CONFIG_HOME/wires`, else `~/.config/wires`. Keep it short on macOS,
since the control socket lives under it and socket paths are limited to 104
bytes.

| File | Written by | Holds |
|---|---|---|
| `node.seed` | `id`, `init` | This node's secret key (0600). Its public half is the node id. |
| `root.seed` | `init` | The admin's root signing key (0600). Admin machine only. |
| `roster.json`, `names.json` | `init`, `invite`, `remove` | The admin's member set and labels (0600). Admin machine only. |
| `membership.json`, `inclusion-proof.json`, `roster-head.json`, `keyring/` | `join`, re-keys from the channel | This node's credentials, the head it enforces, and the channel keys. |
| `roster-directory.json` | re-keys from the channel | Every member's proof under the current head (0600). |
| `channel.json` | `init`, `join` | The channel name, so `watch`, `call` and `serve` need no argument. |
| `directory.json` | `tools`, `call` | The cached host directory. |
| `tools.json` | `tools add` | Local aliases (optional). |
| `idp-token.jwt` | `login` | The caller's ID token (0600). |
| `inbox/` | `inbox`, `watch` | Pushed messages: `new/` unread (at most 256, oldest evicted with a note), `read/` the last 1024 (0700). |
| `push-queue.json` | `serve` | A host's undelivered pushes (0600). |
| `topics/`, `run/` | `watch`, `serve` | The channel log and the control socket. |

Secrets resolve **flag → environment variable → `--…-file` → keystore**, so
a container can mount its node key from a secret with `--node-seed-file`.

## Revocation

`serve` re-reads the roster head once per connection, so a removal
takes effect on the next call, with no restart. A refused call prints
`wires: denied by responder: <reason>` on stderr, writes nothing to stdout,
exits `77`, and appears on the channel. The commit that removes a member
re-keys everyone else, so the removed member can't read what comes next.
The protocol as built: [docs/protocol.md](docs/protocol.md).

## Reachability

By default a node is found by id through iroh's n0 discovery and relays,
which needs outbound internet. A host's announcement carries its addresses and
relay, so a caller that has read it needs no discovery. To avoid n0's relays,
run upstream [`iroh-relay`](https://docs.rs/iroh-relay) yourself and pass
`--relay-url <its url>` to `serve`, `call`, `watch` and `login`
([docs/deployment.md](docs/deployment.md)).
Addresses are unsigned hints: iroh still authenticates the peer's key, so a
wrong address can only fail to connect.

## Layout, build and test

Two crates in one Cargo workspace ([CLAUDE.md](CLAUDE.md)):

- **`library/`**: the transport-free core. `membership/` (identity,
  membership, the committed roster, invites, re-keys, the channel key),
  `channel/` (topics, envelopes, chain, admission, replay, records,
  announcements), `calls/` (session frames, invocations, audit records, IdP
  claims, pushes).
- **`wires/`**: the binary, filed by role: `admin/`, `host/`, `caller/`,
  `channel/`, and `e2e/` for the loopback integration tests.

```bash
cargo build --workspace
cargo test --workspace                   # unit, property, e2e and doc tests
./.scripts/demo-remote-cli.sh --quiet    # the demo, as a test
docker build -t wires .                  # distroless image, native arch
```

`make help` lists the same as shortcuts. Deployment notes are in
[docs/deployment.md](docs/deployment.md), tests in
[docs/testing.md](docs/testing.md), and the benchmark in
[bench/REPORT.md](bench/REPORT.md).
