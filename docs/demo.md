# The recorded demo: laptop ↔ workbench, Claude Code as the agent

*Script for [card 08](board/doing/08-demo-two-machine.md)'s two-machine run.
Every command here is the current CLI (cards 12–15, 19). The same sequence
runs self-asserting on one machine as `./.scripts/demo-remote-cli.sh`: run
that first, and if it's red, don't record.*

Every sentence of narration has to survive one honest line from someone who
runs remote MCP servers behind Tailscale today ([storytelling.md](storytelling.md) §1).
The answers to the four rebuttals we expect are [at the end](#rebuttals-one-line-each).

## Cast

| Terminal | Machine | `WIRES_HOME` | Role |
|---|---|---|---|
| **admin** | laptop | `~/.wires-admin` | holds the root key; invites and removes |
| **workbench** | workbench (x86_64 Linux, no inbound ports) | `~/.wires-demo` | `wires serve host.json`: one tool, `db_query` |
| **agent** | laptop | `~/.wires-agent` | Claude Code, calling `wires call db_query` from Bash |
| **observer** | laptop (or a second laptop) | `~/.wires-obs` | `wires watch` |

Keep `WIRES_HOME` short: the control socket lives under it, and macOS limits
socket paths to 104 bytes.

## Before recording (off camera)

**Google OAuth.** Create a "Desktop app" OAuth client in Google Cloud. Its
secret isn't confidential for that client type. On the laptop:

```bash
export WIRES_OIDC_CLIENT_ID=<id>.apps.googleusercontent.com   # login reads these
export WIRES_OIDC_CLIENT_SECRET=<secret>
export WIRES_OIDC_AUDIENCE=$WIRES_OIDC_CLIENT_ID               # watch accepts this client id
```

**workbench.** Build natively there (`cargo build --release -p wires`, or
`docker build .`); nothing cross-compiles. Use `ssh -o RemoteCommand=none`
because the ssh config forces a remote command. Put
`orders.db` in the directory `wires serve` runs from, and this `host.json`
beside it:

```json
{
  "version": 1,
  "channel": "ops",
  "identity": { "issuers": [
    { "issuer": "https://accounts.google.com", "audiences": ["<id>.apps.googleusercontent.com"] }
  ] },
  "roles": { "analyst": [ { "email": "<your address>@gmail.com" } ] },
  "tools": {
    "db_query": {
      "description": "Read-only SQL (sqlite3) over the workbench's orders.db; pass the SQL statement as the argument.",
      "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"],
      "allow": ["analyst"]
    }
  }
}
```

**Provision** (this can be on camera, but it's slow viewing):

```bash
admin$     WIRES_HOME=~/.wires-admin wires init --channel ops
workbench$ WIRES_HOME=~/.wires-demo  wires id        # → send to admin
admin$     WIRES_HOME=~/.wires-admin wires invite <workbench id> --name workbench
workbench$ WIRES_HOME=~/.wires-demo  wires join <token>
workbench$ WIRES_HOME=~/.wires-demo  wires serve --check host.json
workbench$ WIRES_HOME=~/.wires-demo  wires serve host.json    # under a supervisor (card 08 used systemd-run --user)
                                                              # note its "share to bootstrap:" ticket
agent$     WIRES_HOME=~/.wires-agent wires id
observer$  WIRES_HOME=~/.wires-obs   wires id
admin$     WIRES_HOME=~/.wires-admin wires invite <agent id> --name agent --peer <workbench ticket>
admin$     WIRES_HOME=~/.wires-admin wires invite <observer id> --name observer
agent$     WIRES_HOME=~/.wires-agent wires join <token>
observer$  WIRES_HOME=~/.wires-obs   wires join <token>
```

**Claude Code for the agent.** Run it with `WIRES_HOME=~/.wires-agent` in its
environment and allow only the one tool:

```bash
WIRES_HOME=~/.wires-agent claude --allowedTools 'Bash(wires call db_query:*)'
```

Don't present that Bash rule as a sandbox. Claude Code still auto-allows
read-only commands like `cat` in the working directory
([agent-sandbox.md](agent-sandbox.md)), so start Claude Code from an empty
directory. If asked, the airtight setups are a container whose `PATH` holds
only `wires` (plus locked mode once card 20 lands), or `wires mcp` with no
Bash tool at all.

## The recording

Show three panes: workbench, agent (Claude Code), and observer. Keep admin in
a fourth pane or a tab.

### 1. The workbench has no way in

```bash
workbench$ ss -ltnp          # TCP listeners: nothing from wires
workbench$ ss -lunp | grep wires   # UDP sockets: iroh's QUIC
```

> "This is the workbench. It's running `wires serve` with one tool: read-only
> SQL on an orders database. It has no TCP listener, and no firewall port
> opened. Unauthenticated peers are refused at the handshake. What it does
> have is a key."

Never say "no ports". iroh binds UDP for QUIC, and `ss -lunp` shows it.

### 2. The observer is watching

```bash
observer$ WIRES_HOME=~/.wires-obs wires watch
```

> "This is someone I trust to watch. They have no credentials for my laptop
> or for the workbench. They're a member of the channel, and that's all."

### 3. Before sign-in the agent sees nothing, and is refused

```bash
agent$ WIRES_HOME=~/.wires-agent wires tools
agent$ WIRES_HOME=~/.wires-agent wires call db_query -- "select count(*) from orders"   # exit 77
```

> "My agent's machine joined with one invite from me. It knows the workbench
> exists, because the workbench announced itself on the channel. It can't see
> any tools yet. The workbench only runs `db_query` for a verified analyst, so
> this call is refused. The refusal shows up for the observer too."

Point at the observer's `✗ … no identity claim …` line.

### 4. Sign in once

```bash
agent$ WIRES_HOME=~/.wires-agent wires login --topic ops     # browser: Google
agent$ WIRES_HOME=~/.wires-agent wires tools                 # db_query  on <host8>  Read-only SQL …
```

> "I sign in with Google. The ID token names this machine's key, because the
> key's hash is the sign-in nonce. The observer checks Google's signature
> itself. There's no wires service in the middle vouching for me. The
> workbench checked it too, found me in `analyst`, and now shows me
> `db_query`, and only me."

Point at `🪪 identity … is <you>@gmail.com (verified by https://accounts.google.com)`.

### 5. The agent works

Prompt in Claude Code:

> *Using `wires call db_query -- "<sql>"` (SQLite, table
> `orders(customer, total, placed_at)`), which customer has the highest total
> spend, and what share of all revenue is that?*

> "Claude Code is calling the remote CLI the way it calls any CLI. Each call
> appears for the observer as it happens: my email, the role that let it
> through, the SQL, the exit code, and how many bytes came back. The
> workbench wrote those lines under its own key, and the agent can't write a
> line that carries that key."

Point at the `▶ … <you>@gmail.com … [analyst] db_query "select …"` and
`■ … exit 0 · … ms · … B out` pairs.

If someone asks about MCP, show that the same tool works through `wires mcp`
for clients that can't run a CLI, and say it exists only for backward
compatibility.

### 5b. The workbench calls back (push)

Self-asserting on one machine: `./.scripts/demo-push.sh` (`--quiet`: about
20 s). For the recording, add the mock CI to the workbench's `host.json`
beside `db_query`. Copy `.scripts/fixtures/ci.sh` to the workbench and use
its absolute path as `<ci>`:

```json
  "tools": {
    "db_query": { … },
    "deploy": { "command": ["<ci>", "deploy"], "allow": ["analyst"],
                "description": "Start a CI build in the background: deploy -- build <n>. Returns at once; the result is pushed to your wires inbox." },
    "logs":   { "command": ["<ci>", "logs"],   "allow": ["analyst"],
                "description": "A build's log: logs -- build <n> [--tail N]." }
  },
  "push": { "allow": ["analyst"] }
```

Start `wires serve` with `CI_JOB_SECS=90 CI_JOBS=~/ci-jobs` in its
environment. The build's background job runs `wires push --to
"$WIRES_CALLER_NODE" …`, which reaches the running `serve` over its control
socket, because the job inherits serve's `WIRES_HOME`. Let Claude Code run
`wires inbox` as well: `--allowedTools 'Bash(wires call:*),Bash(wires inbox:*)'`.

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
> no webhook URL and no open port, and the agent was never reachable from
> the internet. The message names the host key that sent it, and the agent
> checked that key when it connected. Woken, the agent reads the log from the
> same host, and the observer sees the whole chain: deploy, then the push,
> then the logs call, each line stamped with who."

Point at `▶ … deploy build 41`, then `⇢ … "build-41" fetched`, then
`▶ … logs build 41 --tail 50`.

If the agent had been asleep (no inbox running), the push waits on the
workbench (`⇢ … queued`), and the agent's next `wires inbox` fetches it.

Pushed text is input to the model from someone else. The line names the
verified sender so the model (and you) can tell who said it; it doesn't make
the content trustworthy.

What waiting costs, measured (`bench/push/REPORT.md`): with `--wait`, 4 turns
and about 15k input tokens whatever the build length, and about 2 s from failure
to the follow-up. Polling a status tool, or `wires inbox` on a loop, costs the
same as each other and grows with the wait (28k tokens at 60 s, 39k at 300 s),
with a reaction time of 20–180 s.

### 6. Revoke

```bash
admin$ WIRES_HOME=~/.wires-admin wires remove agent
```

Then ask Claude Code the question again.

> "One command. The channel is re-keyed. The workbench picked up the new
> roster from the channel, with no import and no restart. The agent's next
> call exits 77 with nothing on stdout, and the refusal is on the channel as
> well."

Point at `🔑 re-key to roster version …` and then `✗ … db_query denied: roster
inclusion rejected: …`.

### Closing line

> "One CLI on another machine, reached by key; the caller verified by my IdP;
> every call recorded by the machine that ran it, where anyone I trust can
> watch."

## Things not to say

- "No ports" or "no attack surface". Say: no TCP listener, no firewall port
  opened, and unauthenticated peers are refused at the handshake.
- "MCP schemas bloat context." Tool search already handles that. The measured
  win comes from filtering output before it reaches context (bench/REPORT.md).
- "The agent can only run wires." That's true of a container that holds only
  `wires`, not of a Bash permission rule.
- "Join by domain." It isn't built (card 18).

## Rebuttals, one line each

| They say | We say |
|---|---|
| **"Tailscale already does this."** | Tailscale exposes the service to your machine, a network path to the host; wires gives a key-addressed path to one allowlisted CLI, with no TCP listener and no firewall port opened. |
| **"Our MCP gateway already logs every call."** | The gateway's log belongs to whoever runs the gateway and covers only traffic routed through it; this record is written by the machine that ran the command, and a member reads it without either end's credentials. |
| **"We already have Okta / enterprise-managed auth."** | Good, wires uses it: the host enforces your IdP's signed token, bound to the caller's key, and every reader verifies it against your IdP directly, with no wires identity service and no auth code in the CLI. |
| **"A leaner MCP server would close the gap."** | Mostly, yes, because the token win comes from output size; a CLI gets it without rewriting anything, and wires doesn't rest on tokens anyway, it rests on reach, identity and the host-written record. |
| **"Use webhooks."** | The laptop agent has no public endpoint; ngrok or Funnel would put one on the internet. Wires pushes to the agent's key, with nothing exposed. |
| **"Just poll."** | Polling (status tool or inbox loop) cost 28k→39k tokens as the build went 60→300 s and reacted in 20–180 s; `inbox --wait` cost 15k flat and reacted in ~2 s (bench/push/REPORT.md). |
| **"A2A has push."** | Through webhooks to a public URL, the same problem. |
| **"The MCP tasks extension."** | Poll-based by design (`tasks/get`): the "just poll" row. |
