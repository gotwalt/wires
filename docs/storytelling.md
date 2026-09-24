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
