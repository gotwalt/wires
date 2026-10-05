# Storytelling: the rebuttal test

*The test every README and narration sentence must pass, and the
conventions the self-asserting demo scripts follow.*

## 1. The rebuttal test

**A story is dead if one honest sentence from an informed skeptic kills it.**
Write the story on paper first — a page, no code — and attack it as someone
who already runs remote MCP servers and already has Tailscale. If it dies,
it dies for the cost of a page instead of a week of scripting and a recording.

Three candidate stories died this way in a single sitting, before any code was
written. Logged here so we don't re-propose them:

| Candidate | The rebuttal that killed it |
|---|---|
| **The tool that isn't in the box** — the agent uses a tool whose API key it can never see | Any remote MCP server already keeps its env vars server-side. This is table stakes the moment the tool isn't a local child process. |
| **Steal the config** — the ticket sits in plaintext in the client config and is worthless if copied | If a bearer token leaks, the operator rotates it and moves on. Token theft is routine and already remediable. |
| **No inbound port** | Tailscale. (Also: not honestly recordable on loopback — needs two physical machines.) |

The pattern in the failures is worth more than the failures. All three stories
have the same shape — **one client, one server** — and in that shape *the
server operator already holds every authority the story is selling*: admit,
refuse, scope, revoke. A pitch built on those is a pitch for a nicer
implementation of something that already works.

### Corollary: what the core story is *not*

"Access control and network connectivity for remote MCPs" is a **category**,
not a story. It has no protagonist, no antagonist, and no turn, and a viewer
files it next to Tailscale + OAuth and scrolls on. Any one-liner also has to
pass the register test: no "substrate," "fabric," or "capability-gated."

### The story that survives, and its sharpest attacks

The core is stated once, on the [board](board/README.md) ("The one idea"),
and every doc quotes or paraphrases that statement rather than writing its
own. Its clause-by-clause rebuttals are the board's table. The ones a
skeptic reaches for first, and the answers that hold:

| Attack | The answer |
|---|---|
| **"That's `ssh host cmd`."** | SSH approaches solve a different problem. SSH, Tailscale SSH and Teleport give a person a login on a machine; wires gives a person a named service wherever it runs, with no account or shell on the host. Don't argue TTY versus process: `ssh host cmd` runs one command with no TTY. The difference is machine versus service. |
| **"That's Tailscale."** | Tailscale gives a machine a route to another machine's ports; whatever listens there still does its own sign-in. wires gives a person a route to the services the signed policy lets them call, checked against their IdP sign-in on every call, with no inbound port. |
| **"That's a remote MCP server."** | That is a tool call whose result arrives whole; wires runs a CLI whose output the agent filters first, under one policy for every service, with a per-person catalog and a way back to an agent that isn't connected. Argue it on results, not schemas: with tool search on, schemas cost about 400 tokens ([bench/REPORT.md](../bench/REPORT.md)). And don't claim framing overhead: nobody measured it. |
| **"Where's the audit log?"** | There isn't one. The host writes one ordinary log line per call; wires keeps no other record. Say so; don't imply one. |

### Claim only what the code does

A sentence that is true of a card in `backlog/` but not of the code at
`HEAD` fails the test as surely as a rebuttal does. Several hosts for a
service means failover, not load spreading; MCP is a bridge, not the goal;
a person is removed by email (`wires remove <email>`), not by removing
one of their machines. Limits are stated once, in the limits section, not hedged in every
sentence.

### One word per thing

*network* (not "fabric": that is only a field name), *policy* for the
admin-signed document (not "registry", "state" or "signed list"), *sign-in*
and *ID token* for the credential, *host*, *directory*, *service*, *role*,
*view* (what a caller holds), *push* and *inbox*. Words for things that are
gone stay out of the story: badge, membership, invite, reader, call log.

## 2. Conventions for the demo scripts

- **`--quiet` is the test; narrated mode is the screencast.** Same script,
  same run, no separate fixture (`.scripts/demo-remote-cli.sh`).
- **Pacing lives in the script.** It is the edit suite, and it is what makes a
  recording reproducible by anyone with the repo.
- **Cold open.** The payoff must be visible in the first ~8 seconds.
- **One belief per story**, and **name the weakness**: every story asks the
  viewer to grant some premise; writing it down keeps us from believing our
  own demo.
- **Show "today, without wires."** The counterfactual is the beat most likely
  to be missing.
