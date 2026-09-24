# The recorded demo: laptop ↔ workbench, Claude Code as the agent

*Script for [card 08](board/doing/08-demo-two-machine.md)'s two-machine run.
Every command here is the current CLI. The same sequence runs self-asserting
on one machine as `./.scripts/demo-remote-cli.sh`: run that first, and if
it's red, don't record.*

Every sentence of narration has to survive one honest line from someone who
runs remote MCP servers behind Tailscale today ([storytelling.md](storytelling.md) §1).
The one-line answers to the rebuttals we expect are in the
[cheat sheet](#rebuttals-one-line-each).

## Cheat sheet

Set these once per terminal, so every command below is bare `wires …`:

| Terminal | Environment |
|---|---|
| **admin** (laptop) | `export WIRES_HOME=~/.wires-admin` |
| **workbench** (`ssh -o RemoteCommand=none workbench`) | `export WIRES_HOME=~/.wires-demo`; `cd` to the directory with `host.json` and `orders.db` |
| **agent** (laptop, Claude Code) | `export WIRES_HOME=~/.wires-agent WIRES_OIDC_CLIENT_ID=… WIRES_OIDC_CLIENT_SECRET=…` |
| **reader** (laptop or second laptop) | `export WIRES_HOME=~/.wires-reader WIRES_OIDC_CLIENT_ID=… WIRES_OIDC_CLIENT_SECRET=…` |

Off camera: `./.scripts/demo-remote-cli.sh --quiet` is green, [provisioning](#before-recording-off-camera)
is done, `wires serve host.json` is running on the workbench, and the reader is logged in.
On camera, in order:

| Beat | Terminal | Command | What appears |
|---|---|---|---|
| 1 | workbench | `ss -ltnp` then `ss -lunp \| grep wires` | no TCP listener from wires; UDP sockets (QUIC) only |
| 2 | agent | `wires services` | nothing on stdout; stderr `wires services: no service allows this node without a login (policy vN)` |
| 2 | agent | `wires call orders-db -- "select count(*) from orders"; echo $?` | ``wires: denied by host: no ID token presented; run `wires login` ``, then `77` |
| 3 | agent | `wires login` | browser: Google, then the "signed in" page |
| 3 | agent | `wires services` | `orders-db  Read-only SQL (sqlite3) over …  (analyst)` |
| 4 | agent | `claude --allowedTools 'Bash(wires call orders-db:*)'`, then [the prompt](#4-the-agent-works) | Claude Code runs `wires call orders-db -- "…"`; the answer is umbrella, $999.00 of $1,629.84 (61.3%) |
| 5 | reader | `wires watch orders-db` | `▶ … <you>@gmail.com (…) [analyst] orders-db "select …"`, `■ … exit 0 · … ms · … B out`, and a `✗ … no ID token presented` line for beat 2 |
| 5 (opt.) | reader (second tab) | `wires call orders-db -- "select 1"` | exit 77: `… is in no role allowed to call orders-db (analyst)`; a `✗` in the watch |
| 5b (opt.) | agent | [push beat](#5b-the-workbench-calls-back-push): `wires call deploy -- build 41`, `wires inbox --wait --timeout 10m` | `… from host <wb8> (verified)  build-41  failed: …` |
| 5c (with a spare) | workbench | stop `wires serve`, ask again | the spare answers (`wires call --verbose` names it) |
| 6 | admin | `wires remove agent` | stderr `policy version N: published to 1 of 1 directory(ies)` (2 of 2 with a spare that is also a directory) |
| 6 | agent | ask Claude Code the question again | exit 77, nothing on stdout: `wires: denied by host: not a member of this network`; no `✗` in the watch (a banned node's knock is traced by the host, not logged) |

### Rebuttals, one line each

| They say | We say |
|---|---|
| **"Tailscale already does this."** | Tailscale gives your machine a network path to the host; wires gives a key-addressed path to the services a signed list lets you call, with no TCP listener and no firewall port opened. |
| **"Our MCP gateway already logs every call."** | The gateway's log belongs to whoever runs the gateway and covers only traffic routed through it; this record is written and signed by the machine that ran the command, and the readers the admin names read it without either end's credentials. |
| **"We already have Okta / MCP's enterprise-managed auth."** | Good, wires uses the same IdP. In MCP's extension the IdP decides which servers you reach and each server's authorization server still issues its tokens; here every host checks the IdP's own ID token, bound to the caller's key, against one admin-signed list for every service, with no auth code in the CLI. |
| **"A leaner MCP server would close the gap."** | Mostly, yes, because the token win comes from output size; a CLI gets it without rewriting anything, and wires doesn't rest on tokens anyway, it rests on reach, identity and the host-written record. |
| **"Can't the host just edit its log?"** | It can withhold or truncate its own history, but a rewrite of anything a reader has already seen breaks the hash chain at that reader's mark, and `wires watch` stops with an alarm. A witness that holds copies is [card 09](board/backlog/09-witness.md), not built. |
| **"Use webhooks."** | The laptop agent has no public endpoint; ngrok or Funnel would put one on the internet. Wires pushes to the agent's key, with nothing exposed. |
| **"Just poll."** | Polling (status service or inbox loop) cost 28k→39k tokens as the build went 60→300 s and reacted in 20–180 s; `inbox --wait` cost 15k flat and reacted in ~2 s (bench/push/REPORT.md). |
| **"A2A has push."** | Through webhooks to a public URL, the same problem. |
| **"The MCP tasks extension."** | Polling `tasks/get` is its default; status can also arrive as `notifications/tasks` on a `subscriptions/listen` stream the client holds open. Neither reaches an agent that isn't connected; that is working-group work, not in the 2026-07-28 spec. |

## Cast

| Terminal | Machine | `WIRES_HOME` | Role |
|---|---|---|---|
| **admin** | laptop | `~/.wires-admin` | holds the root key; mints badges; signs the trusted IdP, roles, services, bans and directories |
| **workbench** | workbench (x86_64 Linux, no firewall port opened) | `~/.wires-demo` | `wires serve host.json`: implements `orders-db`, and is the network's directory |
| **spare** (optional) | a second host | `~/.wires-spare` | implements `orders-db` too, for the failover beat |
| **agent** | laptop | `~/.wires-agent` | Claude Code, calling `wires call orders-db` from Bash |
| **reader** | laptop (or a second laptop) | `~/.wires-reader` | a member in role `security`: `wires watch orders-db` |

Keep `WIRES_HOME` short: a host's control socket lives under it, and macOS
limits socket paths to 104 bytes.

## Before recording (off camera)

**Google OAuth.** Create a "Desktop app" OAuth client in Google Cloud. Its
secret isn't confidential for that client type. On the laptop:

```bash
export WIRES_OIDC_CLIENT_ID=<id>.apps.googleusercontent.com   # init and login read these
export WIRES_OIDC_CLIENT_SECRET=<secret>
```

**workbench.** Build natively there (`cargo build --release -p wires`, or
`docker build .`); nothing cross-compiles. Use `ssh -o RemoteCommand=none`
because the ssh config forces a remote command. Make `orders.db` in the
directory `wires serve` runs from (`sqlite3 orders.db < .scripts/fixtures/orders.sql`),
and put this `host.json` beside it (the loopback demo's
`.scripts/fixtures/host.json`; the trusted IdP is the signed policy's, which
`init` sets, so an `identity` section is optional and could only narrow it):

```json
{
  "version": 2,
  "services": {
    "orders-db": { "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"] }
  },
  "push": { "allow": ["analyst"] }
}
```

**Provision** (this can be on camera, but it's slow viewing):

```bash
admin$     WIRES_HOME=~/.wires-admin wires init             # trusts Google, with $WIRES_OIDC_CLIENT_ID
admin$     WIRES_HOME=~/.wires-admin wires role set analyst '<your address>@gmail.com'
admin$     WIRES_HOME=~/.wires-admin wires role set security '<the reader's address>'
workbench$ WIRES_HOME=~/.wires-demo  wires id        # → send to admin
admin$     WIRES_HOME=~/.wires-admin wires invite <workbench id> --name workbench
admin$     WIRES_HOME=~/.wires-admin wires directory add workbench   # it holds the policy for the others
admin$     WIRES_HOME=~/.wires-admin wires service add orders-db \
             --description "Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument." \
             --allow analyst --reader security --host workbench     # (--host spare too, if you have one)
admin$     WIRES_HOME=~/.wires-admin wires invite <workbench id> --name workbench   # a token with the service in it
workbench$ WIRES_HOME=~/.wires-demo  wires join <token>
workbench$ WIRES_HOME=~/.wires-demo  wires serve --check host.json
workbench$ WIRES_HOME=~/.wires-demo  wires serve host.json    # under a supervisor (card 08 used systemd-run --user)
agent$     WIRES_HOME=~/.wires-agent  wires id
reader$    WIRES_HOME=~/.wires-reader wires id
admin$     WIRES_HOME=~/.wires-admin wires invite <agent id> --name agent      # no edit: nothing is published
admin$     WIRES_HOME=~/.wires-admin wires invite <reader id> --name reader
agent$     WIRES_HOME=~/.wires-agent  wires join <token>
reader$    WIRES_HOME=~/.wires-reader wires join <token>
reader$    WIRES_HOME=~/.wires-reader wires login     # as the reader's address
```

The workbench is invited twice because it was offline when it was named the
directory and assigned the service (those edits exit 1: no directory was
up): the second token carries the newer policy (re-joining never rolls one
back). Every later admin change is published to the running workbench, which
is the directory, and the agent and reader fetch it from there. Machines find each other by key through n0 discovery; on a network
without it, copy the workbench's `run/hint` line into the others'
`$WIRES_HOME/hints`.

**Claude Code for the agent.** Run it with `WIRES_HOME=~/.wires-agent` in its
environment and allow only the one service:

```bash
WIRES_HOME=~/.wires-agent claude --allowedTools 'Bash(wires call orders-db:*)'
```

Don't present that Bash rule as a sandbox. Claude Code still auto-allows
read-only commands like `cat` in the working directory
([agent-sandbox.md](agent-sandbox.md)), so start Claude Code from an empty
directory. If asked, the airtight setups are a container whose `PATH` holds
only `wires` with `WIRES_LOCKED=1`, or `wires mcp` with no Bash tool at all.

## The recording

Show three panes: workbench, agent (Claude Code), and reader. Keep admin in a
fourth pane or a tab.

### 1. The workbench has no way in

```bash
workbench$ ss -ltnp          # TCP listeners: nothing from wires
workbench$ ss -lunp | grep wires   # UDP sockets: iroh's QUIC
```

> "This is the workbench. It implements one service: read-only SQL on an
> orders database. It has no TCP listener, and no firewall port opened.
> Anyone can knock, but a key outside the list is refused at its first
> message, before anything runs. What it does have is a key."

Never say "no ports". iroh binds UDP for QUIC, and `ss -lunp` shows it.

### 2. Before sign-in the agent sees nothing, and is refused

```bash
agent$ WIRES_HOME=~/.wires-agent wires services      # nothing
agent$ WIRES_HOME=~/.wires-agent wires call orders-db -- "select count(*) from orders"   # exit 77
```

> "My agent's machine joined with one invite from me. The admin-signed list
> it holds says `orders-db` is for analysts, and it hasn't said who it is yet,
> so it sees nothing, and asking by name is refused with the reason."

### 3. Sign in once

```bash
agent$ WIRES_HOME=~/.wires-agent wires login       # browser: Google
agent$ WIRES_HOME=~/.wires-agent wires services    # orders-db  Read-only SQL …  (analyst)
```

> "I sign in with Google. The ID token names this machine's key, because the
> key's hash is the sign-in nonce. `wires services` checks my identity
> against the list the admin signed, right here, with no network: I'm an
> analyst, so I see `orders-db`. I never name a machine."

### 4. The agent works

Prompt in Claude Code:

> *Using `wires call orders-db -- "<sql>"` (SQLite, table
> `orders(customer, total, placed_at)`), which customer has the highest total
> spend, and what share of all revenue is that?*

> "Claude Code is calling the remote CLI the way it calls any CLI. The
> workbench checks my token and the signed list on every call, runs sqlite3,
> and writes each call into its own signed log."

If someone asks about MCP, open Claude.ai with the `wires` connector
(`https://wires.positivesum.ai/mcp`) and ask the same question there. The
call lands in the same host log with your Google identity as the verified
principal (the dialing node is the gateway's). The line: "wires works in the
MCP clients you already use. The web gateway passes your own sign-in
through, so the machine that runs the call still checks who you are itself."
(`wires mcp` does the same over stdio for desktop clients.)

### 5. The reader reads the records

```bash
reader$ WIRES_HOME=~/.wires-reader wires watch orders-db
```

> "This is someone the admin put in the `security` role, which may read
> `orders-db`'s records. They have no credentials for my laptop or for the
> workbench, and they can't call the service. They see every call: my email,
> the role that let it through, the SQL, the exit code, how many bytes came
> back. The workbench wrote and signed those lines, and the reader checks
> every signature and every link."

Point at the `▶ … <you>@gmail.com (…) [analyst] orders-db "select …"` and
`■ … exit 0 · … ms · … B out` pairs, and at the `✗` line for the refusal in
beat 2. The agent's own `wires watch` shows only its own person's calls: the
isolation boundary is the verified person, so another person's agent sees
none of these (only hash links, which reveal how many entries and when).

### 5b. The workbench calls back (push)

Self-asserting on one machine: `./.scripts/demo-push.sh --quiet`. For the
recording, copy `.scripts/fixtures/ci.sh` to the workbench and add its
services to `host.json` (absolute path as `<ci>`; `.scripts/fixtures/push-host.json`
is the loopback version):

```json
  "services": {
    "orders-db": { … },
    "deploy": { "command": ["<ci>", "deploy"] },
    "logs":   { "command": ["<ci>", "logs"] }
  },
```

register them (`wires service add deploy --allow analyst --host workbench
--description "Start a CI build in the background: deploy -- build <n>. Returns
at once; the result is pushed to your wires inbox."`, likewise `logs`), and
restart `wires serve` with `CI_JOB_SECS=90 CI_JOBS=~/ci-jobs` in its
environment. The build's background job runs `wires push --to
"$WIRES_CALLER_NODE" …`, which reaches the running `serve` through the call's
push capability: with `push` in `host.json`, `serve` gives every call's child
`WIRES_PUSH_SOCKET` and `WIRES_PUSH_TOKEN`, good for pushing to that call's
caller only, for the call and 10 minutes after it (keep `CI_JOB_SECS` under
that). The child never gets the host's keystore. Let Claude Code
run `wires inbox` as well: `--allowedTools 'Bash(wires call:*),Bash(wires inbox:*)'`.

Prompt in Claude Code:

> *Start build 41 with `wires call deploy -- build 41`. The CI pushes you a
> message when it finishes: run `wires inbox --wait --timeout 10m` in the
> background, and when it returns, read the log with `wires call logs --
> build 41 --tail 50` and tell me which test failed and why.*

```bash
agent$ wires call deploy -- build 41                  # returns at once: started build-41
agent$ wires inbox --wait --timeout 10m               # background command; the agent goes quiet
# ~90 s later, on the workbench, the job runs:  wires push --to "$WIRES_CALLER_NODE" --subject build-41 -- "failed: …"
agent$ # inbox exits:  2026-…Z  from host <wb8> (verified)  build-41  failed: test_orders_total …
agent$ wires call logs -- build 41 --tail 50
```

> "The agent started a build and went quiet. It isn't polling. When the build
> failed, the workbench pushed the result to the agent's key. My laptop has
> no webhook URL, and the agent was never reachable from the internet. The
> message names the host key that sent it, and the agent checked that key
> when it connected. Woken, the agent reads the log from the same host."

`wires watch` (the agent's own) shows the chain: `▶ … deploy build 41`, then
`⇢ … "build-41" delivered|fetched`, then `▶ … logs build 41 --tail 50`.

If the agent had been asleep (no inbox running), the push waits on the
workbench (`queued`), and the agent's next `wires inbox` fetches it.

Pushed text is input to the model from someone else. The line names the
verified sender so the model (and you) can tell who said it; it doesn't make
the content trustworthy.

What waiting costs, measured (`bench/push/REPORT.md`): with `--wait`, 4 turns
and about 15k input tokens whatever the build length, and about 2 s from failure
to the follow-up. Polling a status service, or `wires inbox` on a loop, costs the
same as each other and grows with the wait (28k tokens at 60 s, 39k at 300 s),
with a reaction time of 20–180 s.

### 5c. (With a spare) the workbench goes down

Stop `wires serve` on the workbench and ask the question again.

> "Same command. The admin listed two hosts for `orders-db`; the workbench
> didn't answer, so the call went to the spare. The agent never named either."

### 6. Revoke

```bash
admin$ WIRES_HOME=~/.wires-admin wires remove agent
```

Then ask Claude Code the question again.

> "One command. The admin signed a new list without the agent and pushed it
> to the workbench. The workbench applies it from the next call, with no
> restart and no key to rotate. The agent's next call exits 77 with nothing on
> stdout."

Point at `wires: denied by host: not a member of this network` and the
exit code.

### Closing line

> "One CLI on another machine, called by name and reached by key; the caller
> verified by my IdP against a list I signed; every call recorded by the
> machine that ran it, for the people I chose."

## Things not to say

- "No ports" or "no attack surface". Say: no TCP listener, no firewall port
  opened, and a key outside the list is refused at its first message.
- "Refused at the handshake." Any key completes iroh's handshake; the refusal
  comes at the first wires message, before anything runs.
- "MCP schemas bloat context." Tool search already handles that. The measured
  win comes from filtering output before it reaches context (bench/REPORT.md).
- "The agent can only run wires." That's true of a container that holds only
  `wires`, not of a Bash permission rule.
- "Encrypted", "channel", "everyone can watch". Records are read from each
  host by the readers the registry names, in full; everyone else sees only
  their own person's.
- "Nothing about other people reaches the agent." Every machine holds the
  whole signed list: every role and service (cards 36–37 fix that).
- "Join by domain." It isn't built (card 18).

