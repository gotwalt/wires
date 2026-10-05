# The two-machine demo: laptop ↔ workbench, Claude Code as the agent

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
| **agent** (laptop, Claude Code) | `export WIRES_HOME=~/.wires-agent` (empty until beat 3) |

Off camera: `./.scripts/demo-remote-cli.sh --quiet` is green,
[provisioning](#before-recording-off-camera) is done, and `wires serve
host.json` is running on the workbench (it is also the network's
directory). Have the network string (`wires network` on the admin) in the
clipboard. On camera, in order:

| Beat | Terminal | Command | What appears |
|---|---|---|---|
| 1 | workbench | `ss -ltnp` then `ss -lunp \| grep wires` | no TCP listener from wires; UDP sockets (QUIC) only |
| 2 | agent | `wires call orders-db -- "select count(*) from orders"; echo $?` | ``wires: this node has not joined a network: run `wires login <network>` (a caller) or `wires join <network>` (a host or directory) with the string your admin prints with `wires network` ``, then `1` (nothing was dialed) |
| 3 | agent | `wires login <network>` | browser: Google, then the "signed in" page; stderr ``wires login: 1 service(s) you may call (policy version N); see `wires services` `` |
| 3 | agent | `wires services` | `orders-db  Read-only SQL (sqlite3) over …  (analyst)` |
| 4 | agent | `claude --allowedTools 'Bash(wires call orders-db:*)'`, then [the prompt](#4-the-agent-works) | Claude Code runs `wires call orders-db -- "…"`; the answer is umbrella, $999.00 of $1,629.84 (61.3%) |
| 4 (opt.) | workbench | the `serve` output | one `call finished service=orders-db … email="<you>@gmail.com" role=analyst exit=0 …` line per call |
| 5 | agent | [push beat](#5-the-workbench-calls-back-push): `wires call deploy -- build 41`, `wires inbox --wait --timeout 10m` | `… from host <wb8> (verified)  build-41  failed: …` |
| 5b (with a spare) | workbench | stop `wires serve`, ask again within 15 minutes | the spare answers (`wires call --verbose` names it) |
| 6 | admin | `wires remove <your address>` | stderr `policy version N: published to 1 of 1 directory(ies)` (2 of 2 with a spare that is also a directory) |
| 6 | agent | ask Claude Code the question again | exit 77, nothing on stdout: `wires: denied by host: not admitted to this network: no role in this network matches <your address>, or you were removed: ask your admin` |

### Rebuttals, one line each

| They say | We say |
|---|---|
| **"Tailscale already does this."** | Tailscale gives your machine a network path to the host; wires gives a key-addressed path to the services a signed policy lets you call, with no TCP listener and no firewall port opened. |
| **"That's just SSH."** | SSH, Tailscale SSH and Teleport give a person a login on a machine; wires gives a person a named service wherever it runs, with no account or shell on the host. |
| **"We already have Okta / MCP's enterprise-managed auth."** | Good, wires uses the same IdP. In MCP's extension the IdP decides which servers you reach and each server's authorization server still issues its tokens; here every host checks the IdP's own ID token, bound to the caller's key, against one admin-signed policy for every service, with no auth code in the CLI. |
| **"Our MCP gateway already logs every call."** | wires doesn't replace that and keeps no record of its own: each host writes one log line per call, with the verified person, to its own output, for your log collector. |
| **"A leaner MCP server would close the gap."** | Mostly, yes, because the token win comes from output size; a CLI gets it without rewriting anything, and wires' job is reach and identity: making the CLI reachable by name, as you. |
| **"Use webhooks."** | The laptop agent has no public endpoint; ngrok or Funnel would put one on the internet. Wires pushes to the agent's key, with nothing exposed. |
| **"Just poll."** | Polling (status service or inbox loop) cost 28k→39k tokens as the build went 60→300 s and reacted in 20–180 s; `inbox --wait` cost 15k flat and reacted in ~2 s (bench/push/REPORT.md). |
| **"A2A has push."** | Through webhooks to a public URL, the same problem. |
| **"The MCP tasks extension."** | Polling `tasks/get` is its default; status can also arrive as `notifications/tasks` on a `subscriptions/listen` stream the client holds open. Neither reaches an agent that isn't connected; that is working-group work, not in the 2026-07-28 spec. |
| **"Two hosts, so it scales?"** | For a service that keeps no state between calls, yes: each call goes to one of its hosts at random. The hosts share nothing but the policy, so what a service keeps (its memory, its disk, its push queue) stays on the host the call landed on. |

## Cast

| Terminal | Machine | `WIRES_HOME` | Role |
|---|---|---|---|
| **admin** | laptop | `~/.wires-admin` | holds the root key; signs the trusted IdP, roles, services, removals and directories |
| **workbench** | workbench (x86_64 Linux, no firewall port opened) | `~/.wires-demo` | `wires serve host.json`: implements `orders-db`, and is the network's directory |
| **spare** (optional) | a second host | `~/.wires-spare` | implements `orders-db` too, for the beat where the workbench goes down |
| **agent** | laptop | `~/.wires-agent` | Claude Code, calling `wires call orders-db` from Bash |

## Before recording (off camera)

**Google OAuth.** Create a "Desktop app" OAuth client in Google Cloud. Its
secret isn't confidential for that client type. `wires init` signs the client
id into the policy and keeps the secret in the admin's keystore; the network
string carries both, so the agent's `wires login <network>` needs no flags.

**workbench.** Build natively there (`cargo build --release -p wires`, or
`docker build .`); nothing cross-compiles. Use `ssh -o RemoteCommand=none`
because the ssh config forces a remote command. Make `orders.db` in the
directory `wires serve` runs from (`sqlite3 orders.db < .scripts/fixtures/orders.sql`),
and put this `host.json` beside it (the loopback demo's
`.scripts/fixtures/host.json` without its `also_require`, which the loopback
run uses to show a host refusing an analyst the policy admits; the trusted IdP
is the signed policy's, which `init` sets, so an `identity` section is
optional and could only narrow it):

```json
{
  "version": 2,
  "services": {
    "orders-db": { "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"] }
  },
  "push": { "allow": ["analyst"] }
}
```

**Provision** (card 41's first run; no step fails and none is repeated):

```bash
admin$     wires init --client-id <id>.apps.googleusercontent.com --public-client-secret <secret>
admin$     wires role set analyst '<your address>@gmail.com'
workbench$ wires id                                        # → the admin
admin$     wires directory add workbench=<workbench id>   # the directory: it holds the policy for the others
admin$     wires service add orders-db \
             --description "Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument." \
             --allow analyst --host workbench             # (--host spare=<id> too, if you have one)
admin$     wires network                                   # one string, for every machine
workbench$ wires join <network>
workbench$ wires serve --check host.json
workbench$ wires serve host.json        # under a supervisor (card 08 used systemd-run --user); waits for the first publish
admin$     wires policy push
```

Until the workbench has taken a publish, each admin edit says the policy is
stored on the admin and succeeds; `wires policy push` is the one bootstrap
step. Every later admin change is published to the running workbench, which
is the directory, so its host side has it at once. The agent's keystore
stays empty until beat 3: its whole onboarding is `wires login <network>`,
and it holds no policy, only its view (the services its person may use).
Machines find each other by key through n0 discovery; on a network without
it, copy the workbench's `run/hint` line into the others'
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
only `wires` with `WIRES_LOCKED=1` (locked, `wires call` refuses data on
stdin, so `< file` can't ship a file), or `wires mcp` with no Bash tool at all.

## The recording

Show two panes: workbench (with `serve`'s output visible) and agent (Claude
Code). Keep admin in a third pane or a tab.

### 1. The workbench has no way in

```bash
workbench$ ss -ltnp          # TCP listeners: nothing from wires
workbench$ ss -lunp | grep wires   # UDP sockets: iroh's QUIC
```

> "This is the workbench. It implements one service: read-only SQL on an
> orders database. It has no TCP listener, and no firewall port opened.
> Anyone can knock, but a key without a sign-in the policy accepts is
> refused at its first message, before anything runs. What it does have is
> a key."

Never say "no ports". iroh binds UDP for QUIC, and `ss -lunp` shows it.

### 2. Before sign-in the agent has nothing

```bash
agent$ wires call orders-db -- "select count(*) from orders"   # exit 1: run `wires login <network>`
```

> "My agent's machine hasn't joined anything yet. It doesn't know which
> machine runs `orders-db`, or that there is one. Asking by name gets
> nothing, and the message says what to do."

### 3. Sign in once

```bash
agent$ wires login <network>      # browser: Google
agent$ wires services             # orders-db  Read-only SQL …  (analyst)
```

> "The network string is the same for everyone; it can sit in a wiki. I
> sign in with Google, and that is the whole of joining. The ID token names
> this machine's key, because the key's hash is the sign-in nonce. With it,
> the directory gives this machine the services the admin's signed policy
> lets me call, each entry signed by the admin: I'm an analyst, so I see
> `orders-db`. I never name a machine."

### 4. The agent works

Prompt in Claude Code:

> *Using `wires call orders-db -- "<sql>"` (SQLite, table
> `orders(customer, total, placed_at)`), which customer has the highest total
> spend, and what share of all revenue is that?*

> "Claude Code is calling the remote CLI the way it calls any CLI. The
> workbench checks my token and the signed policy on every call and runs
> sqlite3. The output is filtered before it reaches the model, because it's
> a CLI."

If you show the workbench pane: each call adds one `call finished` line
naming my verified email, the role, the exit code and the bytes sent back.
If asked: that line is all wires keeps; there is no signed record.

If someone asks about MCP, open Claude on the web with the `wires` connector
(`https://wires.positivesum.ai/mcp`) and ask the same question there. The
workbench verifies your Google identity itself (the dialing node is the
gateway's). The line: "MCP clients reach the same services through a
bridge. The web gateway passes your own sign-in through, so the machine that
runs the call still checks who you are." (`wires mcp` does the same over
stdio for desktop clients.)

### 5. The workbench calls back (push)

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
that). The child never gets the host's keys. Let Claude Code run
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
> no webhook URL, and the agent was never reachable from the internet. The
> message names the host key that sent it, and the agent checked that key
> when it connected. Woken, the agent reads the log from the same host."

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

### 5b. (With a spare) the workbench goes down

Stop `wires serve` on the workbench and ask the question again.

> "Same command. The admin listed two hosts for `orders-db`, and each call
> goes to one of them at random. The workbench is down, so the spare
> answered: the caller moves to the next host when one can't be reached.
> The agent never named either."

This holds for a while only. Before a caller tells a host anything, the host
must show that a directory other than itself vouched for its policy within
the last 15 minutes (`fresh_secs`), and in this cast the workbench is the
only other directory. The spare answers on the workbench's last word, which
it and the agent hold; about 15 minutes after the workbench stops, calls to
the spare fail with exit 1 (``no directory has vouched for a host of
`orders-db` recently, so nothing was sent``) until the workbench is back. So
record this beat soon after stopping the workbench, and don't say calls keep
working without it. If you want the beat to hold for as long as the
workbench is down, give the network a directory that hosts nothing: on a
third machine (or the laptop, with its own `WIRES_HOME`), `wires id`, the
admin's `wires directory add`, then `wires join <network>` and `wires
directory serve` there, and `wires policy push`. The cast above doesn't
have one.

Then start `wires serve` on the workbench again before step 6: the removal
is published to it, and an admin edit keeps trying a directory it can't
reach for 15 s before it reports the miss (and exits 1, since the workbench
has taken a publish before).

### 6. Remove

```bash
admin$ wires remove <your address>
```

Then ask Claude Code the question again.

> "One command. The admin signed my removal into the policy and published
> it to the directory, which here is the workbench itself. The workbench
> applies it from the next call, with no restart and no key to rotate, and
> it would on any machine I signed in from. The agent's next call exits 77
> with nothing on stdout. The host doesn't tell a removed person apart from
> anyone else it won't admit, on purpose."

Point at `wires: denied by host: not admitted to this network: no role in
this network matches <your address>, or you were removed: ask your admin`
and the exit code. Afterwards, `wires restore <your
address>` puts things back.

### Closing line

> "One CLI on another machine, called by name and reached by key; the caller
> verified by my IdP against a policy I signed; and the machine can call the
> agent back."

## Things not to say

- "No ports" or "no attack surface". Say: no TCP listener, no firewall port
  opened, and a key without an accepted sign-in is refused at its first
  message.
- "Refused at the handshake." Any key completes iroh's handshake; the refusal
  comes at the first wires message, before anything runs.
- "MCP schemas bloat context." Tool search already handles that. The measured
  win comes from filtering output before it reaches context (bench/REPORT.md).
- "The agent can only run wires." That's true of a container that holds only
  `wires`, not of a Bash permission rule.
- "Every call is recorded", "audit trail". wires keeps no record: each host
  writes one log line per call to its own output.
- "Calls keep working with the directory down." They do for up to 15
  minutes (`fresh_secs`); then a caller sends no host anything until a
  directory other than that host vouches for its policy again.
- "Load-balanced." Calls spread at random, blind to how busy each host is.
  Say: calls spread across a service's hosts, which share nothing but the
  policy.
- "The admin approves every machine." Anyone a role admits is in from any
  machine they sign in on.
- "Nothing about other people reaches the agent." Its machine holds only the
  services it may use (with the roles that may call them and their hosts'
  keys). Hosts and directories hold the whole signed policy.
- "Join by domain." It isn't built (card 18).
