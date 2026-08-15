# Storytelling: demos as short stories

*2026-08-14. Written after `.scripts/demo-revoke.sh` proved that a narrated,
self-asserting script makes a watchable introduction to the product, and we
tried to generalize that into a slate of stories. The generalization surfaced
something more useful than a slate: a cheap test that kills a bad pitch on
paper. This doc holds the test, what it killed, and the process for the
stories that survive it.*

See [docs/restart.md](restart.md) for the phase plan this feeds.

---

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

Wires says something genuinely new only when:

- authority is **yours** and spans **many tools**, or
- there is **no client–server pair at all** (the multiway thesis).

Phase 1 is, by construction, a client–server pair. That is why its stories
keep collapsing, and it is a fact about Phase 1's *pitch*, not about the
quality of the drafting.

### Corollary: what the core story is *not*

"Access control and network connectivity for remote MCPs" is a **category**,
not a story. It has no protagonist, no antagonist, and no turn, and a viewer
files it next to Tailscale + OAuth and scrolls on. Any future one-liner has to
survive §1 *and* the restart doc's register test (no "substrate," "fabric," or
"capability-gated").

## 2. The one Phase 1 story that survives

> You gave four agents access to nine tools across three machines. One agent
> is compromised at 2am. Cut it off — all nine, right now, one command,
> without asking nine operators, and without touching the other three agents.

"The server just rotates its keys" does not answer this. The point is not that
*a* server can revoke; it is that you would need nine of them to, each on its
own schedule and dashboard, and most have no concept of "this agent but not
that one" at all. The unit of authority is your root key, not an account on
someone else's system.

Implementable today: several `wires serve` responders on different scopes, one
`roster commit`, every dial dies at once, nothing restarted.

**Its honest weakness, to be written into the story doc rather than hidden:**
in the demo *you* own all nine servers, so the viewer must grant you the
premise that you wouldn't. And the enterprise form of this pitch is called an
IdP, which Okta already sells.

## 3. Where the process should point

Not at manufacturing more Phase 1 stories. Phase 1's gate is already written
in the restart doc and does not depend on any of this: **show the demo we have
to two people who run remote MCP servers today.** If the story is thin, they
will rebut it the way §1 did, and that is the gate working as designed. The
kill criterion is already on paper.

Point the story process at **Phase 2 and Phase 3**, where the rebuttal has no
purchase — there is no server to rotate anything when the story is two agents
and a human sharing one encrypted topic. Write those story docs *before* the
code, per the restart doc's "the spec is the contract" rule: they become the
thing Phase 2 is built against, and they are falsifiable on paper, cheaply.

## 4. The process: four artifacts per story, in order

Type-driven discipline (see CLAUDE.md) applied to narrative — don't skip ahead.

### 4.1 Story doc — `docs/stories/NN-slug.md`

One page, argued and attacked *before* any script exists.

```markdown
# S02 — Take it back

One-liner a viewer repeats to a colleague:
    "He deleted one line and the agent lost the tool — nothing restarted,
     nothing re-keyed."

Cast:            human w/ root key · tool on another machine · agent
Job to be done:  the contractor's access ends today
Today, without wires:
                 rotate the API key → every other consumer breaks with it
                 (SHOW this; don't say it)
The turn:        one signed list, re-signed
Belief earned:   revocation is not a key-rotation event
Belief NOT claimed:
                 nothing about multiway, persistence, or a real network
Rebuttal test:   strongest one-line attack, and the answer — or the story dies
Known weakness:  the premise the viewer must grant us
Proof (assertions):
                 exit 77 · 0 bytes on stdout · responder pid unchanged
Runtime: 60s     Shots: 4 beats
```

The load-bearing lines:

- **Belief earned** — exactly one per story. If it needs two, it is two
  stories.
- **Belief NOT claimed** — the guard against a demo implying Phase 2 exists.
- **Rebuttal test** — §1, applied. No script gets written until this line has
  an answer.
- **Today, without wires** — the counterfactual, and the beat most likely to
  be missing. `demo-revoke.sh` shows the mechanism working but never shows the
  viewer what they would otherwise have had to do, which is exactly why it
  reads as a good scene in search of a movie.

### 4.2 Script — assertions first

`--quiet` mode **is** the test; narrated mode **is** the screencast. Same
script, same run, no separate fixture. This is already how `demo-mcp.sh` and
`demo-revoke.sh` work; it is now the rule.

The narration harness (`say` / `run` / `ok` / `step` / `beat` / `wrapped` /
`indent`, the fresh `mktemp -d`, the cleanup trap) is currently copy-pasted
between those two scripts. **Extract it to `.scripts/lib/story.sh`** before
writing a third. After that a new story is ~40 lines of plot instead of ~300
lines of harness, which is the difference between a repeatable process and an
aspirational one.

### 4.3 Registration as a Bazel test

An `sh_test` per story, running `--quiet`. This is the real lever: **a story
that stops being true breaks CI.** Today the demos rot silently between
recordings.

### 4.4 Recording

Standardized so re-records don't drift visually: fixed terminal geometry,
commit the `.cast` beside the `.gif` (diffable, cheap to re-encode), and a
`make story-rec STORY=<slug>` target wrapping the one-liner already in the
README:

```bash
asciinema rec -c ./.scripts/demo-revoke.sh demo.cast && agg demo.cast docs/demo-revoke.gif
```

## 5. Conventions

- **Pacing lives in the script.** `demo-revoke.sh` says it exactly right:
  pacing here *is* the edit suite. It is also what makes a recording
  reproducible by anyone with the repo.
- **Cold open.** The payoff must be visible in the first ~8 seconds. A looping
  GIF in a README gets about three seconds of attention before someone
  scrolls.
- **The ladder.** Each story is the smallest delta from the previous one, so
  watching them in order builds the model.
- **One belief per story.** See §4.1.
- **Name the weakness in the doc.** Every story asks the viewer to grant some
  premise. Writing it down is what keeps us from believing our own demo.
